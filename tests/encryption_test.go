/*
Copyright 2026 The OpenEBS Authors

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

package tests

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openebs/zfs-localpv/v2/pkg/zfs"
)

var _ = Describe("[zfspv] TEST PER-VOLUME ENCRYPTION", func() {
	Context("App is deployed with zfs driver", func() {
		It("Running per-volume encryption test with a key Secret", encryptionSecretModeTest)
		It("Running per-volume encryption test with generated keys", encryptionAutoModeTest)
		It("Running clone tests of per-volume encrypted volumes", encryptionCloneTest)
	})
})

const (
	encSCName       = "zfspv-sc-enc"
	encAutoSCName   = "zfspv-sc-enc-auto"
	encPlainSCName  = "zfspv-sc-enc-plain"
	encOffSCName    = "zfspv-sc-enc-off"
	encKeySecret    = "zfspv-enc-key"
	encOtherSecret  = "zfspv-enc-other-key"
	encPvcName      = "zfspv-pvc-enc"
	encAppName      = "busybox-zfspv-enc"
	encSnapName     = "zfspv-snap-enc"
	encAutoPvcName1 = "zfspv-pvc-enc-auto-1"
	encAutoPvcName2 = "zfspv-pvc-enc-auto-2"
	encAutoAppName  = "busybox-zfspv-enc-auto"
	encClonePvcName = "zfspv-pvc-enc-clone"
	encCloneAppName = "busybox-zfspv-enc-clone"
	encVolClonePvc  = "zfspv-pvc-enc-vol-clone"

	encVAPName = "openebs-zfs-protect-encryption-keys"
)

// encStorageClass returns a StorageClass manifest on the test pool, with the
// given extra parameters.
func encStorageClass(name string, params map[string]string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "apiVersion: storage.k8s.io/v1\nkind: StorageClass\nmetadata:\n  name: %s\n", name)
	fmt.Fprintf(&b, "provisioner: %s\nparameters:\n  poolname: %q\n  fstype: zfs\n", ZFSProvisioner, POOLNAME)
	for k, v := range params {
		fmt.Fprintf(&b, "  %s: %q\n", k, v)
	}
	return b.String()
}

// encPVC returns a PVC manifest with the given annotations and, if set, data
// source (a PVC name, or "snapshot/<name>" for a VolumeSnapshot).
func encPVC(name, storageClass string, annotations map[string]string, dataSource string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "apiVersion: v1\nkind: PersistentVolumeClaim\nmetadata:\n  name: %s\n", name)
	if len(annotations) != 0 {
		b.WriteString("  annotations:\n")
		for k, v := range annotations {
			fmt.Fprintf(&b, "    %s: %q\n", k, v)
		}
	}
	fmt.Fprintf(&b, "spec:\n  storageClassName: %s\n  accessModes: [ReadWriteOnce]\n", storageClass)
	b.WriteString("  resources:\n    requests:\n      storage: 5Gi\n")
	switch {
	case strings.HasPrefix(dataSource, "snapshot/"):
		fmt.Fprintf(&b, "  dataSource:\n    name: %s\n    kind: VolumeSnapshot\n    apiGroup: snapshot.storage.k8s.io\n",
			strings.TrimPrefix(dataSource, "snapshot/"))
	case dataSource != "":
		fmt.Fprintf(&b, "  dataSource:\n    name: %s\n    kind: PersistentVolumeClaim\n", dataSource)
	}
	return b.String()
}

func kubectlApply(manifest string) {
	stdout, stderr, err := kubectlWithInput([]byte(manifest), "apply", "-n", OpenEBSNamespace, "-f", "-")
	Expect(err).ShouldNot(HaveOccurred(), "stdout=%s, stderr=%s", stdout, stderr)
}

func newHexKey() string {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	Expect(err).ShouldNot(HaveOccurred())
	return hex.EncodeToString(key)
}

func createKeySecret(name string) {
	By("creating the key Secret " + name)
	stdout, stderr, err := kubectl("create", "secret", "generic", name, "-n", OpenEBSNamespace,
		"--from-literal=key="+newHexKey())
	Expect(err).ShouldNot(HaveOccurred(), "stdout=%s, stderr=%s", stdout, stderr)
}

func keySecretValue(name string) string {
	stdout, stderr, err := kubectl("get", "secret", name, "-n", OpenEBSNamespace, "-o", "jsonpath={.data.key}")
	Expect(err).ShouldNot(HaveOccurred(), "stdout=%s, stderr=%s", stdout, stderr)
	key, err := base64.StdEncoding.DecodeString(string(stdout))
	Expect(err).ShouldNot(HaveOccurred())
	return string(key)
}

func setKeySecretValue(name, key string) {
	stdout, stderr, err := kubectl("patch", "secret", name, "-n", OpenEBSNamespace,
		"-p", `{"stringData":{"key":"`+key+`"}}`)
	Expect(err).ShouldNot(HaveOccurred(), "stdout=%s, stderr=%s", stdout, stderr)
}

// zfsCmd runs zfs on the test host, which is the node.
func zfsCmd(args ...string) (string, error) {
	stdout, stderr, err := execAtLocal("sudo", nil, append([]string{zfs.ZFSVolCmd}, args...)...)
	return strings.TrimSpace(string(stdout) + string(stderr)), err
}

// encDataset returns the dataset of the volume of a PVC.
func encDataset(pvcName string) string {
	vol, err := ZFSClient.WithNamespace(OpenEBSNamespace).Get(getZVName(pvcName), metav1.GetOptions{})
	Expect(err).ShouldNot(HaveOccurred(), "while fetching the zfs volume of pvc %s", pvcName)
	return vol.Spec.PoolName + "/" + vol.Name
}

func keyStatus(dataset string) string {
	out, err := zfsCmd("get", "-H", "-o", "value", "keystatus", dataset)
	Expect(err).ShouldNot(HaveOccurred(), out)
	return out
}

// appExec runs a shell script in the pod of an app deployment.
func appExec(appName, script string) string {
	verifyAppPodRunning(appName)
	stdout, stderr, err := kubectl("exec", "-n", OpenEBSNamespace, appPod.Items[0].Name, "--", "sh", "-c", script)
	Expect(err).ShouldNot(HaveOccurred(), "stdout=%s, stderr=%s", stdout, stderr)
	return strings.TrimSpace(string(stdout))
}

// stopApp deletes an app deployment and waits for its pod to be gone.
func stopApp(appName string) {
	deleteAppDeployment(appName)
	Eventually(func() int {
		pods, err := PodClient.WithNamespace(OpenEBSNamespace).
			List(metav1.ListOptions{LabelSelector: "role=test,appName=" + appName})
		Expect(err).ShouldNot(HaveOccurred())
		return len(pods.Items)
	}, 120, 5).Should(BeZero(), "while waiting for the pods of %s to be gone", appName)
}

// unloadKey unloads the key of a dataset, as after a node reboot.
func unloadKey(dataset string) {
	Eventually(func() error {
		_, err := zfsCmd("unload-key", dataset)
		return err
	}, 60, 5).Should(Succeed(), "while unloading the key of %s", dataset)
	Expect(keyStatus(dataset)).To(Equal("unavailable"))
}

func deleteKeySecret(name string) {
	stdout, stderr, err := kubectl("delete", "secret", name, "-n", OpenEBSNamespace, "--ignore-not-found")
	Expect(err).ShouldNot(HaveOccurred(), "stdout=%s, stderr=%s", stdout, stderr)
}

func deleteStorageClassByName(name string) {
	stdout, stderr, err := kubectl("delete", "storageclass", name, "--ignore-not-found")
	Expect(err).ShouldNot(HaveOccurred(), "stdout=%s, stderr=%s", stdout, stderr)
}

// createBoundEncPVC creates a PVC and waits for it to be bound.
func createBoundEncPVC(name, storageClass string, annotations map[string]string, dataSource string) {
	By("creating pvc " + name)
	kubectlApply(encPVC(name, storageClass, annotations, dataSource))
	// IsPVCBoundEventually reads through the shared client, whose namespace is
	// otherwise only set by the helpers that create PVCs with it.
	PVCClient.WithNamespace(OpenEBSNamespace)
	Expect(IsPVCBoundEventually(name)).To(BeTrue(), "while waiting for pvc %s to be bound", name)
}

// expectProvisioningRejected creates a PVC and checks that its provisioning
// fails with a message containing want, then deletes it.
func expectProvisioningRejected(name, storageClass string, annotations map[string]string, dataSource, want string) {
	By("creating pvc " + name + ", expecting its provisioning to fail")
	kubectlApply(encPVC(name, storageClass, annotations, dataSource))
	Eventually(func() string {
		stdout, _, _ := kubectl("get", "events", "-n", OpenEBSNamespace,
			"--field-selector", "involvedObject.name="+name+",reason=ProvisioningFailed",
			"-o", "jsonpath={.items[*].message}")
		return string(stdout)
	}, 120, 5).Should(ContainSubstring(want), "while waiting for the provisioning of pvc %s to fail", name)
	phase, _, _ := kubectl("get", "pvc", name, "-n", OpenEBSNamespace, "-o", "jsonpath={.status.phase}")
	Expect(string(phase)).To(Equal("Pending"), "pvc %s must not be bound", name)
	stdout, stderr, err := kubectl("delete", "pvc", name, "-n", OpenEBSNamespace, "--wait")
	Expect(err).ShouldNot(HaveOccurred(), "stdout=%s, stderr=%s", stdout, stderr)
}

// encKeyRef returns the key Secret reference recorded on the volume of a PVC.
func encKeyRef(pvcName string) (string, string) {
	vol, err := ZFSClient.WithNamespace(OpenEBSNamespace).Get(getZVName(pvcName), metav1.GetOptions{})
	Expect(err).ShouldNot(HaveOccurred(), "while fetching the zfs volume of pvc %s", pvcName)
	Expect(vol.Spec.EncryptionKeyRef).NotTo(BeNil(), "zfs volume of pvc %s has no key reference", pvcName)
	return vol.Spec.EncryptionKeyRef.Name, vol.Spec.EncryptionKeyRef.Namespace
}

// encMarker returns the openebs.io/encrypted attribute of the PV of a PVC.
func encMarker(pvcName string) string {
	stdout, stderr, err := kubectl("get", "pv", getZVName(pvcName),
		"-o", `jsonpath={.spec.csi.volumeAttributes.openebs\.io/encrypted}`)
	Expect(err).ShouldNot(HaveOccurred(), "stdout=%s, stderr=%s", stdout, stderr)
	return string(stdout)
}

// secretData returns a data entry of a Secret in the driver namespace, decoded.
func secretData(name, entry string) string {
	stdout, stderr, err := kubectl("get", "secret", name, "-n", OpenEBSNamespace,
		"-o", "go-template={{index .data \""+entry+"\" | base64decode}}")
	Expect(err).ShouldNot(HaveOccurred(), "stdout=%s, stderr=%s", stdout, stderr)
	return string(stdout)
}

func secretExists(name string) bool {
	_, _, err := kubectl("get", "secret", name, "-n", OpenEBSNamespace)
	return err == nil
}

// keyProtectionInstalled reports whether the chart rendered the admission
// policy protecting the generated keys (Kubernetes >= 1.30).
func keyProtectionInstalled() bool {
	_, _, err := kubectl("get", "validatingadmissionpolicy", encVAPName)
	return err == nil
}

func encryptionSecretModeTest() {
	createKeySecret(encKeySecret)
	kubectlApply(encStorageClass(encSCName, map[string]string{"encryption": "aes-256-gcm"}))

	createBoundEncPVC(encPvcName, encSCName, map[string]string{zfs.PVCEncryptionSecretAnnotation: encKeySecret}, "")
	By("Creating and deploying app pod", func() { createDeployVerifyApp(encAppName, encPvcName) })

	By("verifying the key reference and the PV marker", func() {
		name, ns := encKeyRef(encPvcName)
		Expect(name).To(Equal(encKeySecret))
		Expect(ns).To(Equal(OpenEBSNamespace))
		Expect(encMarker(encPvcName)).To(Equal(zfs.EncryptedVolume))
	})

	dataset := encDataset(encPvcName)
	By("reloading the key at mount after it was unloaded", func() {
		appExec(encAppName, "echo enc-data > /mnt/datadir/enc.txt; sync")
		stopApp(encAppName)
		unloadKey(dataset)
		createDeployVerifyApp(encAppName, encPvcName)
		Expect(keyStatus(dataset)).To(Equal("available"))
		Expect(appExec(encAppName, "cat /mnt/datadir/enc.txt")).To(Equal("enc-data"))
	})

	By("refusing to mount with a changed key", func() {
		stopApp(encAppName)
		unloadKey(dataset)
		key := keySecretValue(encKeySecret)
		setKeySecretValue(encKeySecret, newHexKey())
		createAndDeployAppPod(encAppName, encPvcName)
		Eventually(func() string {
			stdout, _, _ := kubectl("get", "events", "-n", OpenEBSNamespace,
				"--field-selector", "reason=FailedMount", "-o", "jsonpath={.items[*].message}")
			return string(stdout)
		}, 120, 5).Should(ContainSubstring("is incorrect"), "while waiting for the mount to fail")
		Expect(keyStatus(dataset)).To(Equal("unavailable"))
		stopApp(encAppName)
		setKeySecretValue(encKeySecret, key)
		createDeployVerifyApp(encAppName, encPvcName)
		Expect(appExec(encAppName, "cat /mnt/datadir/enc.txt")).To(Equal("enc-data"))
	})

	expectProvisioningRejected("zfspv-pvc-enc-empty", encSCName,
		map[string]string{zfs.PVCEncryptionSecretAnnotation: ""}, "", "is set but empty")
	expectProvisioningRejected("zfspv-pvc-enc-missing", encSCName,
		map[string]string{zfs.PVCEncryptionSecretAnnotation: "zfspv-enc-no-such-key"}, "", "is invalid")
	kubectlApply(encStorageClass(encPlainSCName, nil))
	expectProvisioningRejected("zfspv-pvc-enc-plain", encPlainSCName,
		map[string]string{zfs.PVCEncryptionSecretAnnotation: encKeySecret}, "", "refusing to create an unencrypted volume")
	kubectlApply(encStorageClass(encOffSCName, map[string]string{"encryption": "off"}))
	expectProvisioningRejected("zfspv-pvc-enc-off", encOffSCName,
		map[string]string{zfs.PVCEncryptionSecretAnnotation: encKeySecret}, "", "refusing to create an unencrypted volume")
	By("provisioning a volume on a StorageClass with encryption off", func() {
		createBoundEncPVC("zfspv-pvc-enc-off-plain", encOffSCName, nil, "")
		Expect(encMarker("zfspv-pvc-enc-off-plain")).To(BeEmpty())
		deletePVC("zfspv-pvc-enc-off-plain")
	})

	By("Deleting application deployment")
	deleteAppDeployment(encAppName)
	By("Deleting pvc")
	deletePVC(encPvcName)
	By("verifying the user Secret is left in place", func() { Expect(secretExists(encKeySecret)).To(BeTrue()) })

	deleteKeySecret(encKeySecret)
	deleteStorageClassByName(encPlainSCName)
	deleteStorageClassByName(encOffSCName)
	deleteStorageClassByName(encSCName)
}

func encryptionAutoModeTest() {
	kubectlApply(encStorageClass(encAutoSCName, map[string]string{
		"encryption":              "aes-256-gcm",
		"autoCreateEncryptionKey": "true",
	}))
	createBoundEncPVC(encAutoPvcName1, encAutoSCName, nil, "")
	createBoundEncPVC(encAutoPvcName2, encAutoSCName, nil, "")

	keys := map[string]string{}
	By("verifying each volume has its own generated key", func() {
		for _, pvcName := range []string{encAutoPvcName1, encAutoPvcName2} {
			vol := getZVName(pvcName)
			name, ns := encKeyRef(pvcName)
			Expect(name).To(Equal(zfs.AutoKeySecretName(vol)))
			Expect(ns).To(Equal(OpenEBSNamespace))
			Expect(encMarker(pvcName)).To(Equal(zfs.EncryptedVolume))

			labels, stderr, err := kubectl("get", "secret", name, "-n", OpenEBSNamespace,
				"-o", "jsonpath={.metadata.labels}")
			Expect(err).ShouldNot(HaveOccurred(), "stderr=%s", stderr)
			Expect(string(labels)).To(ContainSubstring(`"` + zfs.AutoKeySecretLabel + `":"true"`))
			Expect(string(labels)).To(ContainSubstring(`"` + zfs.AutoKeyVolumeLabel + `":"` + vol + `"`))
			Expect(secretData(name, "volume")).To(Equal(vol))
			keys[pvcName] = secretData(name, "key")
			Expect(keys[pvcName]).To(HaveLen(64))
		}
		Expect(keys[encAutoPvcName1]).NotTo(Equal(keys[encAutoPvcName2]), "generated keys must differ")
	})
	By("Creating and deploying app pod", func() { createDeployVerifyApp(encAutoAppName, encAutoPvcName2) })

	if keyProtectionInstalled() {
		By("verifying the admission policy denies deleting a generated key", func() {
			stdout, stderr, err := kubectl("delete", "secret", zfs.AutoKeySecretName(getZVName(encAutoPvcName1)),
				"-n", OpenEBSNamespace)
			Expect(err).Should(HaveOccurred(), "stdout=%s", stdout)
			Expect(string(stderr)).To(ContainSubstring("denied"))
		})
	}

	By("verifying the generated key is deleted with its volume", func() {
		secret := zfs.AutoKeySecretName(getZVName(encAutoPvcName1))
		deletePVC(encAutoPvcName1)
		Eventually(func() bool { return secretExists(secret) }, 120, 5).Should(BeFalse(),
			"while waiting for the generated key %s to be deleted", secret)
	})

	By("Deleting application deployment")
	deleteAppDeployment(encAutoAppName)
	deletePVC(encAutoPvcName2)
	deleteStorageClassByName(encAutoSCName)
}

func encryptionCloneTest() {
	createKeySecret(encKeySecret)
	createKeySecret(encOtherSecret)
	kubectlApply(encStorageClass(encSCName, map[string]string{"encryption": "aes-256-gcm"}))
	keyAnnotation := map[string]string{zfs.PVCEncryptionSecretAnnotation: encKeySecret}
	otherAnnotation := map[string]string{zfs.PVCEncryptionSecretAnnotation: encOtherSecret}

	createBoundEncPVC(encPvcName, encSCName, keyAnnotation, "")
	By("Creating and deploying app pod", func() { createDeployVerifyApp(encAppName, encPvcName) })

	createSnapshot(encPvcName, encSnapName)
	verifySnapshotCreated(encSnapName)

	createBoundEncPVC(encClonePvcName, encSCName, nil, "snapshot/"+encSnapName)
	By("Creating and deploying clone app pod", func() { createDeployVerifyCloneApp(encCloneAppName, encClonePvcName) })
	createBoundEncPVC(encVolClonePvc, encSCName, keyAnnotation, encPvcName)

	By("verifying the clones share their source's key", func() {
		for _, pvcName := range []string{encClonePvcName, encVolClonePvc} {
			name, ns := encKeyRef(pvcName)
			Expect(name).To(Equal(encKeySecret))
			Expect(ns).To(Equal(OpenEBSNamespace))
			Expect(encMarker(pvcName)).To(Equal(zfs.EncryptedVolume))
		}
	})

	expectProvisioningRejected("zfspv-pvc-enc-restore-other", encSCName, otherAnnotation,
		"snapshot/"+encSnapName, "always uses its source's encryption key")
	expectProvisioningRejected("zfspv-pvc-enc-clone-other", encSCName, otherAnnotation,
		encPvcName, "always uses its source's encryption key")

	By("Deleting clone application deployment")
	deleteAppDeployment(encCloneAppName)
	By("Deleting clone pvcs")
	deletePVC(encClonePvcName)
	deletePVC(encVolClonePvc)
	By("Deleting snapshot")
	deleteSnapshot(encPvcName, encSnapName)
	By("Deleting main application deployment")
	deleteAppDeployment(encAppName)
	By("Deleting main pvc")
	deletePVC(encPvcName)

	deleteKeySecret(encOtherSecret)
	deleteKeySecret(encKeySecret)
	deleteStorageClassByName(encSCName)
}
