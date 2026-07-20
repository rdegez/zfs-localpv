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
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	k8sapi "github.com/openebs/lib-csi/pkg/client/k8s"
	apis "github.com/openebs/zfs-localpv/v2/pkg/apis/openebs.io/zfs/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
)

// ZFSLoadKeyArg is the zfs sub-command used to load an encryption key.
const ZFSLoadKeyArg = "load-key"

// PVCEncryptionSecretAnnotation is the PVC annotation naming the Secret that holds
// the volume key.
const PVCEncryptionSecretAnnotation = "encryption.openebs.io/secret-name"

const (
	// AutoKeySecretPrefix prefixes the name of the Secret holding a generated key.
	AutoKeySecretPrefix = "zfs-enc-"
	// AutoKeySecretLabel marks a Secret holding a generated key. The driver never
	// adopts nor deletes a Secret without it.
	AutoKeySecretLabel = "encryption.openebs.io/auto-managed"
	// AutoKeyVolumeLabel records the volume a driver-managed key belongs to.
	AutoKeyVolumeLabel = "encryption.openebs.io/volume"
	// autoKeyVolumeField repeats the volume name in the Secret data, for tools that
	// back the keys up to a KMS (a PushSecret template only sees the data).
	autoKeyVolumeField = "volume"
)

var (
	kubeClientMu sync.Mutex
	kubeClient   kubernetes.Interface
)

// getKubeClient returns a cached Kubernetes clientset. A failed attempt is not
// cached, so it is retried on the next call.
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

// autoKeySecretName returns the name of the Secret holding a volume's generated key.
func autoKeySecretName(volName string) string {
	return AutoKeySecretPrefix + volName
}

// provisionAutoKeySecret generates a key and stores it in an immutable Secret, or
// reuses the Secret if it already exists (e.g. on a retry).
func provisionAutoKeySecret(client kubernetes.Interface, namespace, volName string) (string, string, error) {
	name := autoKeySecretName(volName)
	if existing, err := client.CoreV1().Secrets(namespace).Get(
		context.Background(), name, metav1.GetOptions{}); err == nil {
		// never adopt a Secret the driver did not create
		if existing.Labels[AutoKeySecretLabel] != "true" {
			return "", "", fmt.Errorf(
				"zfs: secret %s/%s already exists and is not driver-managed (missing %s=true label); refusing to reuse it",
				namespace, name, AutoKeySecretLabel)
		}
		return name, namespace, nil
	} else if !k8serrors.IsNotFound(err) {
		return "", "", fmt.Errorf("zfs: get auto key secret %s/%s: %w", namespace, name, err)
	}

	key, err := generateHexKey()
	if err != nil {
		return "", "", err
	}
	// the Secret is the only copy of the key: no edit may replace it
	immutable := true
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				AutoKeySecretLabel: "true",
				AutoKeyVolumeLabel: volName,
			},
		},
		Immutable: &immutable,
		Type:      corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			encryptionSecretKeyField: []byte(key),
			autoKeyVolumeField:       []byte(volName),
		},
	}
	if _, err := client.CoreV1().Secrets(namespace).Create(
		context.Background(), secret, metav1.CreateOptions{}); err != nil {
		if k8serrors.IsAlreadyExists(err) {
			return name, namespace, nil
		}
		return "", "", fmt.Errorf("zfs: create auto key secret %s/%s: %w", namespace, name, err)
	}
	klog.Infof("zfs: created the encryption key secret %s/%s for volume %s", namespace, name, volName)
	return name, namespace, nil
}

// AutoKeySecretName returns the name of the Secret holding a volume's generated key.
func AutoKeySecretName(volName string) string {
	return autoKeySecretName(volName)
}

// ownsAutoKeySecret reports whether vol's key is its own generated key. A clone
// shares its source's key and does not own it.
func ownsAutoKeySecret(vol *apis.ZFSVolume) bool {
	ref := vol.Spec.EncryptionKeyRef
	return ref != nil && ref.Namespace == OpenEBSNamespace && ref.Name == autoKeySecretName(vol.Name)
}

// EnsureAutoKeySecret creates the generated key of vol, right before its dataset.
func EnsureAutoKeySecret(vol *apis.ZFSVolume) error {
	if !ownsAutoKeySecret(vol) {
		return nil
	}
	client, err := getKubeClient()
	if err != nil {
		return err
	}
	_, _, err = provisionAutoKeySecret(client, OpenEBSNamespace, vol.Name)
	return err
}

// RemoveAutoKeySecret deletes the generated key of vol once its dataset is
// destroyed. Deleting a key cannot be undone, so it needs proof that the dataset
// is gone: its parent dataset is available and `zfs list` reports it as missing.
func RemoveAutoKeySecret(vol *apis.ZFSVolume) error {
	if !ownsAutoKeySecret(vol) {
		return nil
	}
	volume := vol.Spec.PoolName + "/" + vol.Name
	if err := getVolume(vol.Spec.PoolName); err != nil {
		return fmt.Errorf("zfs: keeping the encryption key of %s, its parent dataset is not available: %w", volume, err)
	}
	missing, err := datasetMissing(volume)
	if err != nil {
		return fmt.Errorf("zfs: keeping the encryption key of %s, cannot confirm that its dataset is gone: %w", volume, err)
	}
	if !missing {
		return fmt.Errorf("zfs: keeping the encryption key of %s, its dataset still exists", volume)
	}
	return deleteAutoKeySecret(vol)
}

// deleteAutoKeySecret deletes the generated key of vol, without checking its dataset.
func deleteAutoKeySecret(vol *apis.ZFSVolume) error {
	if !ownsAutoKeySecret(vol) {
		return nil
	}
	client, err := getKubeClient()
	if err != nil {
		return err
	}
	return removeAutoKeySecret(client, OpenEBSNamespace, vol.Name)
}

// datasetMissing reports whether `zfs list` says that the dataset does not exist;
// any other failure is returned as an error.
func datasetMissing(dataset string) (bool, error) {
	err := getVolume(dataset)
	if err == nil {
		return false, nil
	}
	if isDatasetMissing(err) {
		return true, nil
	}
	return false, err
}

// isDatasetMissing reports whether err says that the dataset does not exist.
// NOTE: this matches an OpenZFS message; revisit on major ZFS bumps.
func isDatasetMissing(err error) bool {
	var zerr *Error
	return errors.As(err, &zerr) && strings.Contains(zerr.Stderr, "dataset does not exist")
}

func removeAutoKeySecret(client kubernetes.Interface, namespace, volName string) error {
	name := autoKeySecretName(volName)
	s, err := client.CoreV1().Secrets(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if k8serrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("zfs: get auto key secret %s/%s: %w", namespace, name, err)
	}
	if s.Labels[AutoKeySecretLabel] != "true" {
		// Never delete a Secret the driver did not create.
		klog.Warningf("zfs: secret %s/%s is not driver-managed (missing %s=true label); leaving it in place",
			namespace, name, AutoKeySecretLabel)
		return nil
	}
	// Precondition on the UID so a Secret recreated in the meantime is not hit.
	uid := s.UID
	err = client.CoreV1().Secrets(namespace).Delete(context.Background(), name,
		metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}})
	if err != nil && !k8serrors.IsNotFound(err) {
		return fmt.Errorf("zfs: delete auto key secret %s/%s: %w", namespace, name, err)
	}
	klog.Infof("zfs: deleted the encryption key secret %s/%s of volume %s, whose dataset does not exist", namespace, name, volName)
	return nil
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

// UsesManagedKey reports whether vol's key comes from a Secret rather than a
// keylocation file.
func UsesManagedKey(vol *apis.ZFSVolume) bool {
	return vol.Spec.EncryptionKeyRef != nil
}

// ValidateEncryptionSecret checks that the Secret exists and holds a valid key.
func ValidateEncryptionSecret(name, namespace string) error {
	_, err := fetchKeyFromSecret(namespace, name)
	return err
}

// FetchEncryptionKey returns vol's key, read from its Secret.
func FetchEncryptionKey(vol *apis.ZFSVolume) (string, error) {
	ref := vol.Spec.EncryptionKeyRef
	if ref == nil {
		return "", fmt.Errorf("zfs: no encryption key secret referenced")
	}
	return fetchKeyFromSecret(ref.Namespace, ref.Name)
}

// getDatasetProperty returns a zfs property of any dataset.
func getDatasetProperty(dataset, prop string) (string, error) {
	cmd := exec.Command(ZFSVolCmd, ZFSGetArg, "-pH", "-o", "value", prop, dataset)
	out, err := runCmd(cmd, dataset)
	if err != nil {
		return "", NewZFSError(fmt.Sprintf("zfs get %s", prop), dataset, err, out)
	}
	return strings.TrimSpace(string(out)), nil
}

// loadKeyForDataset loads vol's key on the encryption root of dataset, unless it
// is already loaded or the dataset is not encrypted.
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
		// NOTE: these checks match OpenZFS messages; revisit on major ZFS bumps.
		// A concurrent load-key (clones, mounts after a reboot) may have won the race.
		if strings.Contains(string(out), "Key already loaded") {
			klog.Infof("zfs: encryption key already loaded for %s", root)
			return nil
		}
		// a valid but wrong key, e.g. a Secret changed after the volume was created
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

// EnsureKeyLoaded loads vol's key before it is mounted: the keys of
// keylocation=prompt datasets are not loaded on pool import, e.g. after a reboot.
func EnsureKeyLoaded(ctx context.Context, vol *apis.ZFSVolume) error {
	if !UsesManagedKey(vol) {
		return nil
	}
	if err := loadKeyForDataset(vol, vol.Spec.PoolName+"/"+vol.Name); err != nil {
		return err
	}
	// udev creates the zvol device asynchronously after load-key
	if vol.Spec.VolumeType != VolTypeDataset {
		return waitForZvolDevice(ctx, vol)
	}
	return nil
}

const (
	// zvolDeviceWaitDefaultTimeout bounds the wait for an encrypted zvol's device.
	zvolDeviceWaitDefaultTimeout = 10 * time.Second
	// zvolDeviceWaitInterval is the poll interval while waiting for the device.
	zvolDeviceWaitInterval = 100 * time.Millisecond
	// ZvolDeviceWaitTimeoutEnv overrides the wait timeout with a Go duration.
	ZvolDeviceWaitTimeoutEnv = "ZFS_ZVOL_DEVICE_WAIT_TIMEOUT"
)

// zvolDeviceWaitTimeout returns the wait timeout, set by ZFS_ZVOL_DEVICE_WAIT_TIMEOUT.
func zvolDeviceWaitTimeout() time.Duration {
	if v := os.Getenv(ZvolDeviceWaitTimeoutEnv); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
		klog.Warningf("zfs: ignoring invalid %s=%q, using default %s", ZvolDeviceWaitTimeoutEnv, v, zvolDeviceWaitDefaultTimeout)
	}
	return zvolDeviceWaitDefaultTimeout
}

// waitForZvolDevice waits for the device node of an encrypted zvol.
func waitForZvolDevice(ctx context.Context, vol *apis.ZFSVolume) error {
	return waitForDevice(ctx, ZFSDevPath+vol.Spec.PoolName+"/"+vol.Name, zvolDeviceWaitTimeout())
}

// waitForDevice polls for device until it exists, the timeout elapses or ctx is done.
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

// EnsureParentKeyLoaded loads the key of a clone's source, which zfs clone needs,
// e.g. after a reboot.
func EnsureParentKeyLoaded(vol *apis.ZFSVolume) error {
	if !UsesManagedKey(vol) || vol.Spec.SnapName == "" {
		return nil
	}
	src := strings.SplitN(vol.Spec.SnapName, "@", 2)[0]
	if src == "" {
		return nil
	}
	return loadKeyForDataset(vol, vol.Spec.PoolName+"/"+src)
}
