/*
Copyright 2024 The OpenEBS Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package zfs

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	k8sapi "github.com/openebs/lib-csi/pkg/client/k8s"
	apis "github.com/openebs/zfs-localpv/pkg/apis/openebs.io/zfs/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
)

// ZFSLoadKeyArg is the zfs sub-command used to load an encryption key.
const ZFSLoadKeyArg = "load-key"

// PVCEncryptionSecretAnnotation is the PVC annotation naming the Secret (in the
// PVC namespace) that holds the per-volume hex encryption key.
const PVCEncryptionSecretAnnotation = "local.zfs.openebs.io/encryption-secret"

var (
	kubeClientMu sync.Mutex
	kubeClient   kubernetes.Interface
)

// getKubeClient lazily builds and caches a Kubernetes clientset, used to read
// the Secret that holds a volume's encryption key. Both the node
// agent (at create time) and the node plugin (at mount time) rely on it. Only a
// successful client is cached; a transient failure is returned and retried on
// the next call, so one early error does not disable encryption for the
// lifetime of the process.
func getKubeClient() (kubernetes.Interface, error) {
	kubeClientMu.Lock()
	defer kubeClientMu.Unlock()
	if kubeClient != nil {
		return kubeClient, nil
	}
	cfg, err := k8sapi.Config().Get()
	if err != nil {
		return nil, fmt.Errorf("zfs: failed to build kubeconfig: %w", err)
	}
	c, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("zfs: failed to build kube client: %w", err)
	}
	kubeClient = c
	return kubeClient, nil
}

// GetPVC returns the PersistentVolumeClaim identified by namespace/name.
func GetPVC(namespace, name string) (*corev1.PersistentVolumeClaim, error) {
	client, err := getKubeClient()
	if err != nil {
		return nil, err
	}
	return client.CoreV1().PersistentVolumeClaims(namespace).Get(
		context.Background(), name, metav1.GetOptions{})
}

// UsesManagedKey reports whether the volume's encryption key is managed by the
// driver (sourced from a referenced Secret), as opposed to the legacy
// keylocation-file mode.
func UsesManagedKey(vol *apis.ZFSVolume) bool {
	return vol.Spec.EncryptionKeyRef != nil
}

// ValidateEncryptionSecret checks, at provisioning time, that the referenced
// Secret exists and holds a valid hex key, so a misconfigured annotation fails
// fast on the controller with a clear message instead of later on the node.
func ValidateEncryptionSecret(name, namespace string) error {
	_, err := fetchKeyFromSecret(namespace, name)
	return err
}

// FetchEncryptionKey returns the hex encoded encryption key for the volume,
// read from the referenced Kubernetes Secret.
func FetchEncryptionKey(vol *apis.ZFSVolume) (string, error) {
	ref := vol.Spec.EncryptionKeyRef
	if ref == nil {
		return "", fmt.Errorf("zfs: no encryption key secret referenced")
	}
	return fetchKeyFromSecret(ref.Namespace, ref.Name)
}

// SetKeyLocationPrompt sets keylocation=prompt on a dataset so subsequent
// `zfs load-key` operations read the key from stdin.
func SetKeyLocationPrompt(dataset string) error {
	cmd := exec.Command(ZFSVolCmd, ZFSSetArg, "keylocation=prompt", dataset)
	out, err := runCmd(cmd, dataset)
	if err != nil {
		return NewZFSError("zfs set keylocation", dataset, err, out)
	}
	return nil
}

// getDatasetProperty returns a single ZFS property value for an arbitrary
// dataset (unlike GetVolumeProperty which derives the dataset from a
// ZFSVolume).
func getDatasetProperty(dataset, prop string) (string, error) {
	cmd := exec.Command(ZFSVolCmd, ZFSGetArg, "-pH", "-o", "value", prop, dataset)
	out, err := runCmd(cmd, dataset)
	if err != nil {
		return "", NewZFSError(fmt.Sprintf("zfs get %s", prop), dataset, err, out)
	}
	return strings.TrimSpace(string(out)), nil
}

// loadKeyForDataset loads the encryption key (fetched from vol's key source)
// onto the encryption root of the given dataset, unless it is already loaded or
// the dataset is not encrypted. vol supplies the key source (a Secret); the
// dataset may be vol's own dataset or, for clones, the parent it inherits from.
func loadKeyForDataset(vol *apis.ZFSVolume, dataset string) error {
	keystatus, err := getDatasetProperty(dataset, "keystatus")
	if err != nil {
		return err
	}
	switch keystatus {
	case "", "none":
		// not an encrypted dataset
		return nil
	case "available":
		// key already loaded
		return nil
	}

	// keystatus == "unavailable": load the key on the encryption root.
	root, err := getDatasetProperty(dataset, "encryptionroot")
	if err != nil {
		return err
	}
	if root == "" || root == "-" {
		return nil
	}

	key, err := FetchEncryptionKey(vol)
	if err != nil {
		return err
	}

	// zfs load-key reads the key from stdin for keylocation=prompt datasets.
	cmd := exec.Command(ZFSVolCmd, ZFSLoadKeyArg, root)
	cmd.Stdin = strings.NewReader(key + "\n")
	out, err := runCmd(cmd, root)
	if err != nil {
		// NOTE: the two checks below match OpenZFS error-message text ("Key
		// already loaded", "Incorrect key provided"); revisit on major ZFS bumps.
		// A concurrent load-key (clones sharing an encryption root, or a racing
		// mount after reboot) may have loaded the key between our keystatus check
		// and here. ZFS reports this as "Key already loaded"; treat it as success.
		if strings.Contains(string(out), "Key already loaded") {
			klog.Infof("zfs: encryption key already loaded for %s", root)
			return nil
		}
		// A valid-hex but WRONG key (e.g. the referenced Secret value was
		// changed after the volume was created) is rejected by zfs. Surface a
		// clear, actionable error rather than a bare zfs failure.
		if strings.Contains(string(out), "Incorrect key") {
			klog.Errorf("zfs: incorrect encryption key for %v: %s", root, strings.TrimSpace(string(out)))
			return fmt.Errorf("zfs: encryption key for %s is incorrect — the referenced Secret does not match the dataset and may have been changed; the volume cannot be unlocked with it", root)
		}
		zerr := NewZFSError("zfs load-key", root, err, out)
		klog.Errorf("zfs: could not load key for %v error: %s", root, zerr)
		return zerr
	}
	klog.Infof("zfs: loaded encryption key for %s", root)
	return nil
}

// EnsureKeyLoaded makes sure the encryption key for the volume is loaded before
// it is mounted. It is a no-op for unencrypted volumes, for volumes not using a
// managed key, and when the key is already loaded. This is what lets encrypted
// volumes survive a node reboot (ZFS does not auto-load keys for
// keylocation=prompt datasets).
func EnsureKeyLoaded(ctx context.Context, vol *apis.ZFSVolume) error {
	if !UsesManagedKey(vol) {
		return nil
	}
	if err := loadKeyForDataset(vol, vol.Spec.PoolName+"/"+vol.Name); err != nil {
		return err
	}
	// For a zvol, the /dev/zvol/<pool>/<name> device node is created by udev
	// asynchronously once the key becomes available. A mount attempt right after
	// `zfs load-key` can race and fail with ENOENT (observed on node reboot), so
	// wait for the device to appear before returning.
	if vol.Spec.VolumeType != VolTypeDataset {
		return waitForZvolDevice(ctx, vol)
	}
	return nil
}

const (
	// zvolDeviceWaitDefaultTimeout bounds how long we wait for an encrypted
	// zvol's device node to appear after its key is loaded.
	zvolDeviceWaitDefaultTimeout = 10 * time.Second
	// zvolDeviceWaitInterval is the poll interval while waiting for the device.
	zvolDeviceWaitInterval = 100 * time.Millisecond
	// ZvolDeviceWaitTimeoutEnv overrides the wait timeout with a Go duration.
	ZvolDeviceWaitTimeoutEnv = "ZFS_ZVOL_DEVICE_WAIT_TIMEOUT"
)

// zvolDeviceWaitTimeout returns the maximum time to wait for a zvol device
// node, overridable via the ZFS_ZVOL_DEVICE_WAIT_TIMEOUT env var (a Go
// duration such as "20s").
func zvolDeviceWaitTimeout() time.Duration {
	if v := os.Getenv(ZvolDeviceWaitTimeoutEnv); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
		klog.Warningf("zfs: ignoring invalid %s=%q, using default %s", ZvolDeviceWaitTimeoutEnv, v, zvolDeviceWaitDefaultTimeout)
	}
	return zvolDeviceWaitDefaultTimeout
}

// waitForZvolDevice waits for the /dev/zvol/<pool>/<name> device node of an
// encrypted zvol to appear after its key has been loaded. ZFS/udev create the
// node asynchronously, so mounting immediately after `zfs load-key` can race
// and fail with ENOENT. It polls until the device shows up, the timeout
// elapses, or the caller's context is cancelled (e.g. the kubelet RPC deadline).
func waitForZvolDevice(ctx context.Context, vol *apis.ZFSVolume) error {
	return waitForDevice(ctx, ZFSDevPath+vol.Spec.PoolName+"/"+vol.Name, zvolDeviceWaitTimeout())
}

// waitForDevice polls for the given device path to exist, returning nil as soon
// as it does, or an error if the timeout elapses or the context is cancelled.
func waitForDevice(ctx context.Context, device string, timeout time.Duration) error {
	if _, err := os.Stat(device); err == nil {
		return nil
	}
	ticker := time.NewTicker(zvolDeviceWaitInterval)
	defer ticker.Stop()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("zfs: interrupted waiting for encrypted zvol device %s: %w", device, ctx.Err())
		case <-timer.C:
			return fmt.Errorf("zfs: encrypted zvol device %s did not appear within %s after load-key", device, timeout)
		case <-ticker.C:
			if _, err := os.Stat(device); err == nil {
				klog.Infof("zfs: encrypted zvol device %s ready", device)
				return nil
			}
		}
	}
}
