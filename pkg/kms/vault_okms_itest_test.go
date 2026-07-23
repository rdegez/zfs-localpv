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
	"fmt"
	"os"
	"testing"
	"time"
)

// fetchWithRetry reads a key, tolerating OKMS read-after-write eventual
// consistency (a freshly written secret may not be immediately readable on the
// next request). Real usage never hits this — provision (controller) and
// load-key (node) are seconds apart — so this only smooths the back-to-back test.
func fetchWithRetry(t *testing.T, ks KeyStore, ctx context.Context, vol string) (string, error) {
	t.Helper()
	var lastErr error
	for i := 0; i < 20; i++ {
		k, err := ks.FetchKey(ctx, vol)
		if err == nil {
			if i > 0 {
				t.Logf("FetchKey succeeded after %d retries (OKMS read-after-write lag)", i)
			}
			return k, nil
		}
		lastErr = err
		time.Sleep(500 * time.Millisecond)
	}
	return "", lastErr
}

// TestVaultOKMS_Integration exercises the real vault (mtls) provider against a
// live OVHcloud OKMS Secret Manager domain. It is skipped unless OKMS_ITEST=1
// and the cert/key/CA/address env vars are set, so it never runs in CI.
//
//	OKMS_ITEST=1 \
//	OKMS_ADDR="https://<region>.okms.ovh.net/api/<domain-id>" \
//	OKMS_CERT=/path/cert.pem OKMS_KEY=/path/key.pem OKMS_CA=/path/ca.pem \
//	go test ./pkg/kms/ -run TestVaultOKMS_Integration -v
func TestVaultOKMS_Integration(t *testing.T) {
	if os.Getenv("OKMS_ITEST") != "1" {
		t.Skip("set OKMS_ITEST=1 (+ OKMS_ADDR/OKMS_CERT/OKMS_KEY/OKMS_CA) to run the live OKMS test")
	}
	readFile := func(env string) string {
		p := os.Getenv(env)
		if p == "" {
			t.Fatalf("%s not set", env)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s (%s): %v", env, p, err)
		}
		return string(b)
	}

	ks, err := GetKMS(ProviderVault, ProviderInitArgs{
		Config: map[string]interface{}{
			"provider":         "vault",
			"vaultAddress":     os.Getenv("OKMS_ADDR"),
			"vaultAuthMethod":  "mtls",
			"vaultBackendPath": "secret",
			"vaultKeyPrefix":   "zfs-localpv-itest",
			"vaultClientCert":  readFile("OKMS_CERT"),
			"vaultClientKey":   readFile("OKMS_KEY"),
			"vaultCACert":      readFile("OKMS_CA"),
		},
	})
	if err != nil {
		t.Fatalf("build vault KMS: %v", err)
	}
	defer ks.Destroy()

	ctx := context.Background()
	// Use a unique path per run, mirroring real usage (each volume maps to its
	// own KMS path `zfs-localpv/pvc-<uuid>`). Re-writing a just-deleted path hits
	// OKMS's KV2 version-tombstone read-after-write lag; a fresh path does not.
	vol := fmt.Sprintf("itest-okms-%d", time.Now().UnixNano())
	defer func() { _ = ks.RemoveKey(ctx, vol) }()

	// GetOrCreateKey mints and stores a key.
	k1, err := ks.GetOrCreateKey(ctx, vol)
	if err != nil {
		t.Fatalf("GetOrCreateKey: %v", err)
	}
	if err := ValidateHexKey(k1); err != nil {
		t.Fatalf("minted key is not valid hex: %v", err)
	}

	// FetchKey returns the same key.
	k2, err := fetchWithRetry(t, ks, ctx, vol)
	if err != nil {
		t.Fatalf("FetchKey: %v", err)
	}
	if k2 != k1 {
		t.Fatalf("FetchKey mismatch: got %q want %q", k2, k1)
	}

	// GetOrCreateKey is idempotent (does not rotate an existing key).
	k3, err := ks.GetOrCreateKey(ctx, vol)
	if err != nil {
		t.Fatalf("GetOrCreateKey (2nd): %v", err)
	}
	if k3 != k1 {
		t.Fatalf("GetOrCreateKey rotated the key: got %q want %q", k3, k1)
	}

	// RemoveKey deletes it; a subsequent FetchKey must fail.
	if err := ks.RemoveKey(ctx, vol); err != nil {
		t.Fatalf("RemoveKey: %v", err)
	}
	if _, err := ks.FetchKey(ctx, vol); err == nil {
		t.Fatalf("FetchKey after RemoveKey should fail, got nil error")
	}
	t.Logf("OKMS mtls round-trip OK (minted, fetched, idempotent, removed): key len=%d", len(k1))
}
