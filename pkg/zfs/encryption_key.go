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
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	// encryptionSecretKeyField is the data key under which a per-volume
	// encryption key is stored in its Kubernetes Secret.
	encryptionSecretKeyField = "key"
	// hexKeyLen is the length of a 32-byte key encoded as hex (keyformat=hex).
	hexKeyLen = 64
)

// generateHexKey returns a fresh 32-byte key encoded as 64 hex characters,
// suitable for ZFS keyformat=hex (used by auto mode to mint a per-volume key).
func generateHexKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate encryption key: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// validateHexKey checks that key is a 64-character hex string (32 bytes),
// suitable for ZFS keyformat=hex.
func validateHexKey(key string) error {
	if len(key) != hexKeyLen {
		return fmt.Errorf("encryption key must be %d hex chars (32 bytes), got %d", hexKeyLen, len(key))
	}
	if _, err := hex.DecodeString(key); err != nil {
		return fmt.Errorf("encryption key is not valid hex: %w", err)
	}
	return nil
}

// fetchKeyFromSecret reads and validates the per-volume hex key from the named
// Kubernetes Secret (data key "key"), using the shared kube client.
func fetchKeyFromSecret(namespace, name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("zfs: no encryption key secret referenced")
	}
	client, err := getKubeClient()
	if err != nil {
		return "", err
	}
	return fetchKeyFromSecretWithClient(client, namespace, name)
}

// fetchKeyFromSecretWithClient is the client-injectable core of
// fetchKeyFromSecret (kept separate so it is unit-testable with a fake client).
func fetchKeyFromSecretWithClient(client kubernetes.Interface, namespace, name string) (string, error) {
	if namespace == "" {
		return "", fmt.Errorf("zfs: encryption key secret %q has no namespace", name)
	}
	secret, err := client.CoreV1().Secrets(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("zfs: get encryption key secret %s/%s: %w", namespace, name, err)
	}
	raw, ok := secret.Data[encryptionSecretKeyField]
	if !ok {
		return "", fmt.Errorf("zfs: encryption key secret %s/%s has no %q data key",
			namespace, name, encryptionSecretKeyField)
	}
	key := strings.TrimSpace(string(raw))
	if err := validateHexKey(key); err != nil {
		return "", fmt.Errorf("zfs: encryption key secret %s/%s: %w (check for a trailing newline or extra characters)",
			namespace, name, err)
	}
	return key, nil
}
