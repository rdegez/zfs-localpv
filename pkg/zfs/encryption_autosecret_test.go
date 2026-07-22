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
	// Cleanup is handled by an OwnerReference to the ZFSVolume CR, not a
	// finalizer: the Secret must NOT carry one (a finalizer would only create
	// stuck-Terminating windows on teardown).
	if len(s.Finalizers) != 0 {
		t.Errorf("auto key secret must not carry a finalizer, got %v", s.Finalizers)
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
