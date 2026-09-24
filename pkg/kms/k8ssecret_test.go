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

package kms

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

const validHexKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" // 64 chars

func TestValidateHexKey(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		wantErr bool
	}{
		{"valid 64 hex", validHexKey, false},
		{"too short", "abcd", true},
		{"non hex", strings.Repeat("g", 64), true},
		{"empty", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateHexKey(tt.key); (err != nil) != tt.wantErr {
				t.Errorf("ValidateHexKey(%q) err = %v, wantErr %v", tt.key, err, tt.wantErr)
			}
		})
	}
}

func newSecret(ns, name string, data map[string][]byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Data:       data,
	}
}

func TestK8sSecretKMS_FetchKey(t *testing.T) {
	client := fake.NewSimpleClientset(
		newSecret("app", "good", map[string][]byte{SecretKeyField: []byte(validHexKey)}),
		newSecret("app", "badhex", map[string][]byte{SecretKeyField: []byte("nothex")}),
		newSecret("app", "nokey", map[string][]byte{"other": []byte(validHexKey)}),
	)

	newKS := func(name, ns string) (KeyStore, error) {
		return GetKMS(ProviderK8sSecret, ProviderInitArgs{
			Config: map[string]interface{}{
				ConfigSecretName:      name,
				ConfigSecretNamespace: ns,
			},
			Namespace:  ns,
			KubeClient: client,
		})
	}

	t.Run("valid key", func(t *testing.T) {
		ks, err := newKS("good", "app")
		if err != nil {
			t.Fatalf("init: %v", err)
		}
		got, err := ks.FetchKey(context.Background(), "vol-1")
		if err != nil {
			t.Fatalf("FetchKey: %v", err)
		}
		if got != validHexKey {
			t.Errorf("got %q, want %q", got, validHexKey)
		}
		// RemoveKey is a no-op and must not error.
		if err := ks.RemoveKey(context.Background(), "vol-1"); err != nil {
			t.Errorf("RemoveKey should be no-op, got %v", err)
		}
	})

	t.Run("invalid hex rejected", func(t *testing.T) {
		ks, _ := newKS("badhex", "app")
		if _, err := ks.FetchKey(context.Background(), "vol-1"); err == nil {
			t.Error("expected error for non-hex key")
		}
	})

	t.Run("missing data key rejected", func(t *testing.T) {
		ks, _ := newKS("nokey", "app")
		if _, err := ks.FetchKey(context.Background(), "vol-1"); err == nil {
			t.Error("expected error for missing data key")
		}
	})

	t.Run("missing secret rejected", func(t *testing.T) {
		ks, _ := newKS("absent", "app")
		if _, err := ks.FetchKey(context.Background(), "vol-1"); err == nil {
			t.Error("expected error for absent secret")
		}
	})

	t.Run("namespace falls back to args", func(t *testing.T) {
		ks, err := GetKMS(ProviderK8sSecret, ProviderInitArgs{
			Config:     map[string]interface{}{ConfigSecretName: "good"},
			Namespace:  "app",
			KubeClient: client,
		})
		if err != nil {
			t.Fatalf("init: %v", err)
		}
		if _, err := ks.FetchKey(context.Background(), "vol-1"); err != nil {
			t.Errorf("FetchKey with fallback ns: %v", err)
		}
	})
}

func TestGetKMS_UnknownProvider(t *testing.T) {
	if _, err := GetKMS("does-not-exist", ProviderInitArgs{}); err == nil {
		t.Error("expected error for unknown provider")
	}
}
