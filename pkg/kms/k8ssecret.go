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
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	// ProviderK8sSecret is the KeyStore backed by a user provided Kubernetes
	// Secret referenced from the PVC. The user brings their own key.
	ProviderK8sSecret = "k8s-secret"

	// ConfigSecretName / ConfigSecretNamespace are the ProviderInitArgs.Config
	// keys carrying the referenced Secret coordinates.
	ConfigSecretName      = "secretName"
	ConfigSecretNamespace = "secretNamespace"

	// SecretKeyField is the data key inside the referenced Secret that holds
	// the hex encoded encryption key.
	SecretKeyField = "key"

	// hexKeyLen is the expected length of the hex encoded key: 32 bytes = 64
	// hexadecimal characters, matching ZFS keyformat=hex.
	hexKeyLen = 64
)

// k8sSecretKMS reads a per-volume key from a referenced Kubernetes Secret.
// It never generates or deletes the Secret: the user owns the key material.
type k8sSecretKMS struct {
	client    kubernetes.Interface
	name      string
	namespace string
}

var _ = RegisterProvider(Provider{
	UniqueID:    ProviderK8sSecret,
	Initializer: newK8sSecretKMS,
})

func newK8sSecretKMS(args ProviderInitArgs) (KeyStore, error) {
	if args.KubeClient == nil {
		return nil, fmt.Errorf("kms(%s): nil kube client", ProviderK8sSecret)
	}
	name, _ := args.Config[ConfigSecretName].(string)
	if name == "" {
		return nil, fmt.Errorf("kms(%s): missing %q in config", ProviderK8sSecret, ConfigSecretName)
	}
	ns, _ := args.Config[ConfigSecretNamespace].(string)
	if ns == "" {
		ns = args.Namespace
	}
	if ns == "" {
		return nil, fmt.Errorf("kms(%s): missing secret namespace", ProviderK8sSecret)
	}
	return &k8sSecretKMS{client: args.KubeClient, name: name, namespace: ns}, nil
}

func (k *k8sSecretKMS) FetchKey(ctx context.Context, volumeID string) (string, error) {
	secret, err := k.client.CoreV1().Secrets(k.namespace).Get(ctx, k.name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("kms(%s): get secret %s/%s: %w",
			ProviderK8sSecret, k.namespace, k.name, err)
	}
	raw, ok := secret.Data[SecretKeyField]
	if !ok {
		return "", fmt.Errorf("kms(%s): secret %s/%s has no %q data key",
			ProviderK8sSecret, k.namespace, k.name, SecretKeyField)
	}
	// Trim surrounding whitespace/newline: a trailing "\n" (from `echo`,
	// `--from-file`, or a copy-paste) is the single most common way a
	// hex key ends up "64 chars + 1" and gets rejected — tolerate it.
	key := strings.TrimSpace(string(raw))
	if err := ValidateHexKey(key); err != nil {
		return "", fmt.Errorf("kms(%s): secret %s/%s: %w (check for a trailing newline or extra characters)",
			ProviderK8sSecret, k.namespace, k.name, err)
	}
	return key, nil
}

// GetOrCreateKey behaves like FetchKey: the key is supplied by the user, the
// driver never generates it.
func (k *k8sSecretKMS) GetOrCreateKey(ctx context.Context, volumeID string) (string, error) {
	return k.FetchKey(ctx, volumeID)
}

// RemoveKey is a no-op: the referenced Secret is owned by the user.
func (k *k8sSecretKMS) RemoveKey(ctx context.Context, volumeID string) error {
	return nil
}

func (k *k8sSecretKMS) Destroy() {}

// GenerateHexKey returns a fresh 32-byte key encoded as 64 hex characters,
// suitable for ZFS keyformat=hex.
func GenerateHexKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate encryption key: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// ValidateHexKey checks that key is a 64 character hex string (32 bytes),
// suitable for ZFS keyformat=hex.
func ValidateHexKey(key string) error {
	if len(key) != hexKeyLen {
		return fmt.Errorf("encryption key must be %d hex chars (32 bytes), got %d", hexKeyLen, len(key))
	}
	if _, err := hex.DecodeString(key); err != nil {
		return fmt.Errorf("encryption key is not valid hex: %w", err)
	}
	return nil
}
