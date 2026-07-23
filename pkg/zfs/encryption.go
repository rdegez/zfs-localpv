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
	"github.com/openebs/zfs-localpv/pkg/kms"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
)

// ZFSLoadKeyArg is the zfs sub-command used to load an encryption key.
const ZFSLoadKeyArg = "load-key"

// PVCEncryptionSecretAnnotation is the PVC annotation naming the Secret (in the
// PVC namespace) that holds the per-volume hex encryption key.
const PVCEncryptionSecretAnnotation = "local.zfs.openebs.io/encryption-secret"

const (
	// AutoKeySecretPrefix prefixes the name of Secrets auto-created by the
	// driver to hold a generated per-volume key (auto mode).
	AutoKeySecretPrefix = "zfs-enc-"
	// AutoKeySecretLabel marks a Secret as driver-managed, so the driver only
	// ever adopts or takes ownership of Secrets it created itself. User-provided
	// Secrets never carry it.
	AutoKeySecretLabel = "local.zfs.openebs.io/auto-managed"
	// AutoKeyVolumeLabel records the volume a driver-managed key belongs to.
	AutoKeyVolumeLabel = "local.zfs.openebs.io/volume"
)

var (
	kubeClientMu sync.Mutex
	kubeClient   kubernetes.Interface
)

// getKubeClient lazily builds and caches a Kubernetes clientset, used to read
// the Secrets/ConfigMaps that back the encryption key stores. Both the node
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
	// This client reads the Secret / KMS ConfigMap that back a volume's key on
	// every provision and every load-key. The client-go defaults (QPS 5, Burst
	// 10) throttle hard when many encrypted volumes are provisioned or remounted
	// at once (e.g. after a node reboot), so raise them for these read-only,
	// key-source lookups.
	cfg.QPS = 100
	cfg.Burst = 200
	c, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("zfs: failed to build kube client: %w", err)
	}
	kubeClient = c
	return kubeClient, nil
}

// autoKeySecretName returns the deterministic name of the auto-created key
// Secret for a volume.
func autoKeySecretName(volName string) string {
	return AutoKeySecretPrefix + volName
}

// provisionAutoKeySecret generates a per-volume key and stores it in a
// driver-managed Secret in the given namespace, returning its name/namespace.
// It is idempotent: if the Secret already exists (e.g. a CreateVolume retry) it
// is reused so the key does not change.
func provisionAutoKeySecret(client kubernetes.Interface, namespace, volName string) (string, string, error) {
	name := autoKeySecretName(volName)
	if existing, err := client.CoreV1().Secrets(namespace).Get(
		context.Background(), name, metav1.GetOptions{}); err == nil {
		// Only reuse a Secret we actually manage. Refuse to adopt a pre-existing
		// Secret that is not labelled auto-managed, so we never silently treat a
		// user-created Secret as the volume key.
		if existing.Labels[AutoKeySecretLabel] != "true" {
			return "", "", fmt.Errorf(
				"zfs: secret %s/%s already exists and is not driver-managed (missing %s=true label); refusing to reuse it",
				namespace, name, AutoKeySecretLabel)
		}
		return name, namespace, nil
	} else if !k8serrors.IsNotFound(err) {
		return "", "", fmt.Errorf("zfs: get auto key secret %s/%s: %w", namespace, name, err)
	}

	key, err := kms.GenerateHexKey()
	if err != nil {
		return "", "", err
	}
	// The auto Secret is the ONLY copy of a driver-generated key: mark it
	// immutable so a stray `kubectl edit`/patch can't silently corrupt the key
	// and make the volume permanently unmountable. Cleanup on volume deletion is
	// handled by an OwnerReference to the ZFSVolume CR (see SetAutoKeySecretOwner),
	// which lets Kubernetes garbage-collect the Secret on every teardown path.
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
		Data:      map[string][]byte{kms.SecretKeyField: []byte(key)},
	}
	if _, err := client.CoreV1().Secrets(namespace).Create(
		context.Background(), secret, metav1.CreateOptions{}); err != nil {
		if k8serrors.IsAlreadyExists(err) {
			return name, namespace, nil
		}
		return "", "", fmt.Errorf("zfs: create auto key secret %s/%s: %w", namespace, name, err)
	}
	return name, namespace, nil
}

// SetAutoKeySecretOwner binds a driver-managed auto-key Secret to its ZFSVolume
// CR via an OwnerReference, so Kubernetes garbage-collects the Secret whenever
// the CR is deleted. This is the sole cleanup mechanism for the auto Secret and
// covers every teardown path — normal DeleteVolume and out-of-band CR deletions
// the controller never sees alike. No-op for user-provided Secrets and for
// volumes without a managed Secret. Best-effort at the call site.
func SetAutoKeySecretOwner(vol *apis.ZFSVolume) error {
	if vol.Spec.EncryptionKeyRef == nil {
		return nil
	}
	ns, name := vol.Spec.EncryptionKeyRef.Namespace, vol.Spec.EncryptionKeyRef.Name
	// An OwnerReference requires the owner to be in the same namespace; auto
	// Secrets live in the driver namespace, same as the ZFSVolume CR. User
	// Secrets (any namespace) are handled by the label check below anyway.
	if ns != OpenEBSNamespace {
		return nil
	}
	client, err := getKubeClient()
	if err != nil {
		return err
	}
	cr, err := GetZFSVolume(vol.Name)
	if err != nil {
		return err
	}
	for attempt := 0; attempt < 5; attempt++ {
		s, gerr := client.CoreV1().Secrets(ns).Get(context.Background(), name, metav1.GetOptions{})
		if k8serrors.IsNotFound(gerr) {
			return nil
		}
		if gerr != nil {
			return gerr
		}
		if s.Labels[AutoKeySecretLabel] != "true" {
			return nil // user-provided Secret — never take ownership of it
		}
		for _, o := range s.OwnerReferences {
			if o.UID == cr.UID {
				return nil // already owned
			}
		}
		s.OwnerReferences = append(s.OwnerReferences, metav1.OwnerReference{
			APIVersion: apis.SchemeGroupVersion.String(),
			Kind:       "ZFSVolume",
			Name:       cr.Name,
			UID:        cr.UID,
		})
		_, uerr := client.CoreV1().Secrets(ns).Update(context.Background(), s, metav1.UpdateOptions{})
		if uerr == nil || k8serrors.IsNotFound(uerr) {
			return nil
		}
		if !k8serrors.IsConflict(uerr) {
			return uerr
		}
	}
	return fmt.Errorf("zfs: set owner on auto key secret %s/%s: too many conflicts", ns, name)
}

// ProvisionAutoKeySecret generates a per-volume key and stores it in a
// driver-managed Secret in the OpenEBS namespace (auto mode). Returns the
// Secret name/namespace to record on the ZFSVolume CR.
func ProvisionAutoKeySecret(volName string) (string, string, error) {
	client, err := getKubeClient()
	if err != nil {
		return "", "", err
	}
	return provisionAutoKeySecret(client, OpenEBSNamespace, volName)
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
// driver (sourced from a referenced Secret or a KMS), as opposed to the legacy
// keylocation-file mode.
func UsesManagedKey(vol *apis.ZFSVolume) bool {
	return vol.Spec.EncryptionKeyRef != nil || vol.Spec.EncryptionKMSID != ""
}

// kmsConfigMapName returns the name of the ConfigMap holding KMS backend
// configuration sections (overridable via the ZFS_KMS_CONFIGMAP_NAME env var).
func kmsConfigMapName() string {
	if name := os.Getenv("ZFS_KMS_CONFIGMAP_NAME"); name != "" {
		return name
	}
	return kms.DefaultKMSConfigMapName
}

// keyStore builds the KeyStore for the given key source. A non-empty secretName
// selects the user provided Secret backend; otherwise a non-empty kmsID selects
// a backend from the KMS ConfigMap (e.g. Vault).
func keyStore(kmsID, secretName, secretNamespace string) (kms.KeyStore, error) {
	client, err := getKubeClient()
	if err != nil {
		return nil, err
	}

	switch {
	case secretName != "":
		return kms.GetKMS(kms.ProviderK8sSecret, kms.ProviderInitArgs{
			Config: map[string]interface{}{
				kms.ConfigSecretName:      secretName,
				kms.ConfigSecretNamespace: secretNamespace,
			},
			Namespace:  secretNamespace,
			KubeClient: client,
		})
	case kmsID != "":
		provider, cfg, cerr := kms.LoadProviderConfig(client, OpenEBSNamespace, kmsConfigMapName(), kmsID)
		if cerr != nil {
			return nil, cerr
		}
		return kms.GetKMS(provider, kms.ProviderInitArgs{
			KMSID:      kmsID,
			Config:     cfg,
			Namespace:  OpenEBSNamespace,
			KubeClient: client,
		})
	default:
		return nil, fmt.Errorf("zfs: no managed encryption key source")
	}
}

// resolveKeyStore builds the KeyStore for the volume from its spec.
func resolveKeyStore(vol *apis.ZFSVolume) (kms.KeyStore, error) {
	var secretName, secretNamespace string
	if ref := vol.Spec.EncryptionKeyRef; ref != nil {
		secretName, secretNamespace = ref.Name, ref.Namespace
	}
	return keyStore(vol.Spec.EncryptionKMSID, secretName, secretNamespace)
}

// ValidateEncryptionSecret checks, at provisioning time, that the referenced
// Secret exists and holds a valid hex key, so a misconfigured annotation fails
// fast on the controller with a clear message instead of later on the node.
func ValidateEncryptionSecret(name, namespace string) error {
	ks, err := keyStore("", name, namespace)
	if err != nil {
		return err
	}
	defer ks.Destroy()
	_, err = ks.FetchKey(context.Background(), "")
	return err
}

// FetchEncryptionKey returns the hex encoded encryption key for the volume.
func FetchEncryptionKey(vol *apis.ZFSVolume) (string, error) {
	ks, err := resolveKeyStore(vol)
	if err != nil {
		return "", err
	}
	defer ks.Destroy()
	return ks.FetchKey(context.Background(), vol.Name)
}

// ProvisionEncryptionKey ensures a key exists for volName in the KMS identified
// by kmsID, generating and storing a fresh one if needed. It is called on the
// controller at CreateVolume so the key is present before the node agent
// creates the encrypted dataset.
func ProvisionEncryptionKey(kmsID, volName string) error {
	ks, err := keyStore(kmsID, "", "")
	if err != nil {
		return err
	}
	defer ks.Destroy()
	_, err = ks.GetOrCreateKey(context.Background(), volName)
	return err
}

// RemoveEncryptionKey deletes the volume's key from its KMS. It is a no-op for
// user-owned Secrets and for volumes without a managed key.
func RemoveEncryptionKey(vol *apis.ZFSVolume) error {
	if !UsesManagedKey(vol) {
		return nil
	}
	ks, err := resolveKeyStore(vol)
	if err != nil {
		return err
	}
	defer ks.Destroy()
	return ks.RemoveKey(context.Background(), vol.Name)
}

// CleanupEncryptionKey best-effort removes the managed key material for a volume
// that is being destroyed: the KMS-stored key (Vault) and/or the driver-managed
// auto Secret. It is a no-op for user-provided Secrets and unencrypted volumes.
// Called from DeleteVolume so it runs on every path that destroys the CR
// (immediate delete, delete-after-last-snapshot, and create rollback), not only
// the snapshot-less path. Failures are logged, not fatal (zfs destroy does not
// need the key loaded).
func CleanupEncryptionKey(vol *apis.ZFSVolume) {
	if vol == nil {
		return
	}
	// KMS-stored keys (Vault) only. The driver-managed auto Secret is removed on
	// the node side, in the ZFSVolume controller, AFTER the dataset is destroyed
	// (so we never drop the sole key copy of a volume that still exists, and so
	// out-of-band CR deletions are covered) — not here.
	if err := RemoveEncryptionKey(vol); err != nil {
		klog.Warningf("zfs: failed to remove encryption key for %s: %s", vol.Name, err.Error())
	}
}

// writeTempKeyFile writes the hex key to a transient 0600 file and returns its
// path. The caller is responsible for removing it.
func writeTempKeyFile(key string) (string, error) {
	f, err := os.CreateTemp("", "zfs-enc-key-")
	if err != nil {
		return "", fmt.Errorf("zfs: create temp key file: %w", err)
	}
	name := f.Name()
	if err := f.Chmod(0600); err != nil {
		_ = f.Close()
		_ = os.Remove(name)
		return "", err
	}
	if _, err := f.WriteString(key); err != nil {
		_ = f.Close()
		_ = os.Remove(name)
		return "", err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(name)
		return "", err
	}
	return name, nil
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
// the dataset is not encrypted. vol supplies the key source (Secret/KMS); the
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
		// A valid-hex but WRONG key (e.g. the referenced Secret/KMS value was
		// changed after the volume was created) is rejected by zfs. Surface a
		// clear, actionable error rather than a bare zfs failure.
		if strings.Contains(string(out), "Incorrect key") {
			klog.Errorf("zfs: incorrect encryption key for %v: %s", root, strings.TrimSpace(string(out)))
			return fmt.Errorf("zfs: encryption key for %s is incorrect — the referenced key (Secret/KMS) does not match the dataset and may have been changed; the volume cannot be unlocked with it", root)
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

// EnsureParentKeyLoaded loads the key for the dataset a clone is derived from,
// so `zfs clone` (which requires the parent key to be available) succeeds even
// after a node reboot. vol is the clone's ZFSVolume (its Spec carries the same
// key source as the parent, since clones inherit it).
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
