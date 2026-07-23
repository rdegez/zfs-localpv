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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeVault is a minimal in-memory Vault KV v2 server for tests.
type fakeVault struct {
	store map[string]string // volumeID -> hex key
	token string
}

func (f *fakeVault) handler(t *testing.T) http.Handler {
	mux := http.NewServeMux()
	const dataPrefix = "/v1/secret/data/zfs-localpv/"
	const metaPrefix = "/v1/secret/metadata/zfs-localpv/"

	mux.HandleFunc(dataPrefix, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Vault-Token"); got != f.token {
			t.Errorf("expected token %q, got %q", f.token, got)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		vol := strings.TrimPrefix(r.URL.Path, dataPrefix)
		switch r.Method {
		case http.MethodGet:
			v, ok := f.store[vol]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{"data": map[string]string{"key": v}},
			})
		case http.MethodPost, http.MethodPut:
			body, _ := io.ReadAll(r.Body)
			var payload struct {
				Data map[string]string `json:"data"`
			}
			_ = json.Unmarshal(body, &payload)
			f.store[vol] = payload.Data["key"]
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{"version": 1},
			})
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	// Login endpoints (cert / kubernetes): issue f.token as the client token.
	mux.HandleFunc("/v1/auth/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"auth": map[string]interface{}{"client_token": f.token},
		})
	})

	mux.HandleFunc(metaPrefix, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		delete(f.store, strings.TrimPrefix(r.URL.Path, metaPrefix))
		w.WriteHeader(http.StatusNoContent)
	})

	return mux
}

func newVaultForTest(t *testing.T, addr, token string) *vaultKMS {
	ks, err := GetKMS(ProviderVault, ProviderInitArgs{
		Config: map[string]interface{}{
			cfgVaultAddress: addr,
			cfgVaultToken:   token,
		},
	})
	if err != nil {
		t.Fatalf("init vault kms: %v", err)
	}
	return ks.(*vaultKMS)
}

func TestVaultKMS_GetOrCreateFetchRemove(t *testing.T) {
	fake := &fakeVault{store: map[string]string{}, token: "test-token"}
	srv := httptest.NewServer(fake.handler(t))
	defer srv.Close()

	k := newVaultForTest(t, srv.URL, "test-token")
	ctx := context.Background()

	// FetchKey on absent volume -> errKeyNotFound
	if _, err := k.FetchKey(ctx, "vol-1"); !errors.Is(err, errKeyNotFound) {
		t.Fatalf("expected errKeyNotFound, got %v", err)
	}

	// GetOrCreateKey generates and stores a valid hex key
	key, err := k.GetOrCreateKey(ctx, "vol-1")
	if err != nil {
		t.Fatalf("GetOrCreateKey: %v", err)
	}
	if err := ValidateHexKey(key); err != nil {
		t.Fatalf("generated key invalid: %v", err)
	}

	// FetchKey returns the same key
	got, err := k.FetchKey(ctx, "vol-1")
	if err != nil {
		t.Fatalf("FetchKey: %v", err)
	}
	if got != key {
		t.Errorf("FetchKey = %q, want %q", got, key)
	}

	// GetOrCreateKey is idempotent (returns the existing key)
	again, err := k.GetOrCreateKey(ctx, "vol-1")
	if err != nil {
		t.Fatalf("GetOrCreateKey (2nd): %v", err)
	}
	if again != key {
		t.Errorf("GetOrCreateKey not idempotent: %q != %q", again, key)
	}

	// RemoveKey deletes it
	if err := k.RemoveKey(ctx, "vol-1"); err != nil {
		t.Fatalf("RemoveKey: %v", err)
	}
	if _, err := k.FetchKey(ctx, "vol-1"); !errors.Is(err, errKeyNotFound) {
		t.Errorf("expected errKeyNotFound after remove, got %v", err)
	}
}

func TestVaultKMS_MissingAddress(t *testing.T) {
	if _, err := GetKMS(ProviderVault, ProviderInitArgs{
		Config: map[string]interface{}{cfgVaultToken: "t"},
	}); err == nil {
		t.Error("expected error when vaultAddress is missing")
	}
}

// genSelfSignedPEM returns a self-signed cert (usable as CA, server and client
// cert, valid for 127.0.0.1/localhost) and its private key, both PEM encoded.
func genSelfSignedPEM(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "zfs-localpv-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

// TestVaultKMS_ClientCertMTLS proves the provider presents its client
// certificate to a server that requires and verifies one (as OVHcloud OKMS
// does), and sends no bearer token in that mode.
func TestVaultKMS_ClientCertMTLS(t *testing.T) {
	certPEM, keyPEM := genSelfSignedPEM(t)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("append cert to pool")
	}

	fake := &fakeVault{store: map[string]string{}} // token stays "" -> no X-Vault-Token expected
	srv := httptest.NewUnstartedServer(fake.handler(t))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}
	srv.StartTLS()
	defer srv.Close()

	ks, err := GetKMS(ProviderVault, ProviderInitArgs{
		Config: map[string]interface{}{
			cfgVaultAddress:    srv.URL,
			cfgVaultAuthMethod: vaultAuthMTLS,
			cfgVaultClientCert: string(certPEM),
			cfgVaultClientKey:  string(keyPEM),
			cfgVaultCACert:     string(certPEM), // trust the server (self-signed)
		},
	})
	if err != nil {
		t.Fatalf("init vault kms (mTLS): %v", err)
	}
	k := ks.(*vaultKMS)
	if k.token != "" {
		t.Errorf("expected empty token for mtls auth, got %q", k.token)
	}

	ctx := context.Background()
	key, err := k.GetOrCreateKey(ctx, "vol-mtls")
	if err != nil {
		t.Fatalf("GetOrCreateKey over mTLS: %v", err)
	}
	got, err := k.FetchKey(ctx, "vol-mtls")
	if err != nil {
		t.Fatalf("FetchKey over mTLS: %v", err)
	}
	if got != key {
		t.Errorf("FetchKey = %q, want %q", got, key)
	}
}

// TestVaultKMS_CertAuthRequiresCert ensures cert auth without a client cert is
// rejected at init rather than failing later against the server.
func TestVaultKMS_CertAuthRequiresCert(t *testing.T) {
	if _, err := GetKMS(ProviderVault, ProviderInitArgs{
		Config: map[string]interface{}{
			cfgVaultAddress:    "https://okms.example.com/api/x",
			cfgVaultAuthMethod: vaultAuthCert,
		},
	}); err == nil {
		t.Error("expected error for cert auth without a client certificate")
	}
}

// TestVaultKMS_CertLogin exercises stock Vault TLS-certificate auth: the
// provider must exchange its client cert at auth/cert/login for a client token
// and then use that token on KV requests (unlike mtls, which sends no token).
func TestVaultKMS_CertLogin(t *testing.T) {
	certPEM, keyPEM := genSelfSignedPEM(t)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("append cert to pool")
	}

	fake := &fakeVault{store: map[string]string{}, token: "cert-issued-token"}
	srv := httptest.NewUnstartedServer(fake.handler(t))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}
	srv.StartTLS()
	defer srv.Close()

	ks, err := GetKMS(ProviderVault, ProviderInitArgs{
		Config: map[string]interface{}{
			cfgVaultAddress:    srv.URL,
			cfgVaultAuthMethod: vaultAuthCert,
			cfgVaultClientCert: string(certPEM),
			cfgVaultClientKey:  string(keyPEM),
			cfgVaultCACert:     string(certPEM),
		},
	})
	if err != nil {
		t.Fatalf("init vault kms (cert login): %v", err)
	}
	k := ks.(*vaultKMS)
	if k.token != "cert-issued-token" {
		t.Errorf("expected token issued by cert login, got %q", k.token)
	}
	// The issued token must be accepted on a subsequent KV write.
	if _, err := k.GetOrCreateKey(context.Background(), "vol-cert"); err != nil {
		t.Fatalf("GetOrCreateKey after cert login: %v", err)
	}
}
