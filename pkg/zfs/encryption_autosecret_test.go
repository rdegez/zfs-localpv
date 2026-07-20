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
	"testing"

	apis "github.com/openebs/zfs-localpv/v2/pkg/apis/openebs.io/zfs/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestProvisionAutoKeySecret(t *testing.T) {
	client := fake.NewSimpleClientset()
	ns := "openebs"
	vol := "pvc-abc"

	name, gotNs, err := provisionAutoKeySecret(client, ns, vol)
	if err != nil {
		t.Fatalf("provisionAutoKeySecret: %v", err)
	}
	if name != AutoKeySecretPrefix+vol || gotNs != ns {
		t.Fatalf("unexpected ref %s/%s", gotNs, name)
	}

	s, err := client.CoreV1().Secrets(ns).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("secret not created: %v", err)
	}
	if s.Labels[AutoKeySecretLabel] != "true" {
		t.Errorf("secret must be labelled auto-managed, got %v", s.Labels)
	}
	if s.Immutable == nil || !*s.Immutable {
		t.Errorf("auto key secret must be immutable to prevent accidental edits, got %v", s.Immutable)
	}
	// The node deletes the Secret once the dataset is destroyed: no finalizer
	// (stuck-Terminating windows on teardown) and no OwnerReference (deleting the
	// ZFSVolume without destroying its dataset must keep the key).
	if len(s.Finalizers) != 0 {
		t.Errorf("auto key secret must not carry a finalizer, got %v", s.Finalizers)
	}
	if len(s.OwnerReferences) != 0 {
		t.Errorf("auto key secret must not carry an owner reference, got %v", s.OwnerReferences)
	}
	if got := string(s.Data[autoKeyVolumeField]); got != vol {
		t.Errorf("secret must record its volume in the data, got %q", got)
	}
	key := string(s.Data[encryptionSecretKeyField])
	if err := validateHexKey(key); err != nil {
		t.Errorf("stored key invalid: %v", err)
	}

	// Idempotent: a second call reuses the same Secret without changing the key.
	if _, _, err := provisionAutoKeySecret(client, ns, vol); err != nil {
		t.Fatalf("second provision: %v", err)
	}
	s2, _ := client.CoreV1().Secrets(ns).Get(context.Background(), name, metav1.GetOptions{})
	if string(s2.Data[encryptionSecretKeyField]) != key {
		t.Errorf("key changed on retry: %q -> %q", key, string(s2.Data[encryptionSecretKeyField]))
	}
}

func TestProvisionAutoKeySecret_RefusesUnmanaged(t *testing.T) {
	ns := "openebs"
	vol := "pvc-xyz"
	// A pre-existing Secret at the auto-key name that is NOT labelled
	// auto-managed must not be silently adopted as the volume key.
	client := fake.NewSimpleClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      AutoKeySecretPrefix + vol,
			Namespace: ns,
		},
		Data: map[string][]byte{encryptionSecretKeyField: []byte("not-ours")},
	})
	if _, _, err := provisionAutoKeySecret(client, ns, vol); err == nil {
		t.Error("expected refusal to adopt an unlabelled pre-existing secret, got nil")
	}
}

func TestOwnsAutoKeySecret(t *testing.T) {
	saved := OpenEBSNamespace
	OpenEBSNamespace = "openebs"
	defer func() { OpenEBSNamespace = saved }()

	withRef := func(volName, secretName, secretNs string) *apis.ZFSVolume {
		v := &apis.ZFSVolume{}
		v.Name = volName
		if secretName != "" {
			v.Spec.EncryptionKeyRef = &apis.EncryptionKeyReference{Name: secretName, Namespace: secretNs}
		}
		return v
	}
	cases := []struct {
		name string
		vol  *apis.ZFSVolume
		want bool
	}{
		{"own auto key", withRef("pvc-a", AutoKeySecretPrefix+"pvc-a", "openebs"), true},
		{"clone sharing its parent's key", withRef("pvc-clone", AutoKeySecretPrefix+"pvc-a", "openebs"), false},
		{"user secret in the PVC namespace", withRef("pvc-a", "my-key", "apps"), false},
		{"auto-like name in another namespace", withRef("pvc-a", AutoKeySecretPrefix+"pvc-a", "apps"), false},
		{"no key reference", withRef("pvc-a", "", ""), false},
	}
	for _, c := range cases {
		if got := ownsAutoKeySecret(c.vol); got != c.want {
			t.Errorf("%s: ownsAutoKeySecret = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestRemoveAutoKeySecret(t *testing.T) {
	ns := "openebs"
	t.Run("deletes the driver-managed secret", func(t *testing.T) {
		client := fake.NewSimpleClientset()
		if _, _, err := provisionAutoKeySecret(client, ns, "pvc-a"); err != nil {
			t.Fatalf("provision: %v", err)
		}
		if err := removeAutoKeySecret(client, ns, "pvc-a"); err != nil {
			t.Fatalf("remove: %v", err)
		}
		if _, err := client.CoreV1().Secrets(ns).Get(context.Background(), AutoKeySecretPrefix+"pvc-a", metav1.GetOptions{}); err == nil {
			t.Error("driver-managed secret still present after removal")
		}
	})
	t.Run("never deletes an unlabelled secret", func(t *testing.T) {
		client := fake.NewSimpleClientset(&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: AutoKeySecretPrefix + "pvc-b", Namespace: ns},
		})
		if err := removeAutoKeySecret(client, ns, "pvc-b"); err != nil {
			t.Fatalf("remove: %v", err)
		}
		if _, err := client.CoreV1().Secrets(ns).Get(context.Background(), AutoKeySecretPrefix+"pvc-b", metav1.GetOptions{}); err != nil {
			t.Errorf("unlabelled secret must be left in place, got %v", err)
		}
	})
	t.Run("already gone is not an error", func(t *testing.T) {
		if err := removeAutoKeySecret(fake.NewSimpleClientset(), ns, "pvc-c"); err != nil {
			t.Errorf("expected nil for a missing secret, got %v", err)
		}
	})
}
