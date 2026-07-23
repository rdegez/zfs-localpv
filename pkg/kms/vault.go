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
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"
)

const (
	// ProviderVault stores one hex encryption key per volume in a HashiCorp
	// Vault KV v2 secret engine. The driver generates the key at CreateVolume.
	ProviderVault = "vault"

	// Vault config keys (values are strings in the KMS ConfigMap).
	cfgVaultAddress         = "vaultAddress"
	cfgVaultBackendPath     = "vaultBackendPath"
	cfgVaultKeyPrefix       = "vaultKeyPrefix"
	cfgVaultNamespace       = "vaultNamespace"
	cfgVaultSkipVerify      = "vaultSkipVerify"
	cfgVaultCACert          = "vaultCACert"
	cfgVaultAuthMethod      = "vaultAuthMethod"
	cfgVaultToken           = "vaultToken"
	cfgVaultTokenSecretName = "vaultTokenSecretName"
	cfgVaultRole            = "vaultRole"
	cfgVaultAuthPath        = "vaultAuthPath"
	// Client-certificate (mTLS) auth, used e.g. by OVHcloud OKMS. The cert/key
	// can be given inline as PEM, or (preferred) via a kubernetes.io/tls Secret.
	cfgVaultClientCert           = "vaultClientCert"
	cfgVaultClientKey            = "vaultClientKey"
	cfgVaultClientCertSecretName = "vaultClientCertSecretName"

	vaultAuthToken      = "token"
	vaultAuthKubernetes = "kubernetes"
	// vaultAuthCert is stock HashiCorp Vault TLS certificate auth: the client
	// cert is exchanged at auth/<path>/login for a client token.
	vaultAuthCert = "cert"
	// vaultAuthMTLS is for KV v2 endpoints that authenticate purely at the TLS
	// layer with a client certificate and have no login endpoint (e.g. OVHcloud
	// OKMS): present the cert, send no bearer token, do not log in.
	vaultAuthMTLS = "mtls"

	vaultTokenSecretKey = "token"
	vaultDataKey        = "key"

	// writeReadbackTimeout / writeReadbackInterval bound how long GetOrCreateKey
	// waits, after storing a new key, for that key to become readable. A strongly
	// consistent backend (HashiCorp Vault, OpenBao) satisfies this on the first
	// read; some backends (e.g. OVHcloud OKMS) negative-cache a prior 404 for a
	// few seconds, so we wait out that read-after-write window here — on the
	// controller at provisioning time — rather than let the node fail to load the
	// key when it creates the dataset.
	writeReadbackTimeout  = 30 * time.Second
	writeReadbackInterval = 500 * time.Millisecond

	// Retry bounds for rate-limited / transiently-unavailable backends. A burst
	// of concurrent CreateVolume calls can make the KV backend (or a proxy in
	// front of it) answer 429 Too Many Requests or 503; instead of surfacing that
	// as a provisioning error and churning through the CSI retry loop, request()
	// backs off in-process (honoring Retry-After when present) and paces the burst
	// out. Bounded so a persistently overloaded backend still fails eventually
	// rather than hanging; per-operation callers (FetchKey/GetOrCreateKey/
	// RemoveKey) also cut it short via their context, while auth logins use a
	// standalone authRetryBudget (they run before any operation context exists).
	vaultRetryMaxAttempts = 8
	vaultRetryBase        = 500 * time.Millisecond
	vaultRetryMax         = 8 * time.Second

	// authRetryBudget bounds the total time an auth login (cert / kubernetes)
	// spends retrying a rate-limited endpoint. Auth happens while building the
	// client, before any per-operation context exists, so it cannot ride the CSI
	// CreateVolume deadline; this standalone budget keeps a throttled auth
	// endpoint from stalling a provision for the full attempt budget instead.
	authRetryBudget = 30 * time.Second

	// tlsCertKey / tlsKeyKey are the data keys of a kubernetes.io/tls Secret.
	tlsCertKey = "tls.crt"
	tlsKeyKey  = "tls.key"

	// saTokenPath is where the pod's ServiceAccount JWT is mounted, used for
	// Vault Kubernetes auth.
	saTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
)

// errKeyNotFound is returned by fetch when the per-volume secret is absent.
var errKeyNotFound = errors.New("vault: key not found")

// vaultKMS talks to Vault's HTTP API (KV v2) directly, avoiding a heavy SDK
// dependency. It is used both on the controller (generate+store) and the node
// (fetch).
type vaultKMS struct {
	httpc     *http.Client
	addr      string // scheme://host:port, no trailing slash
	token     string
	namespace string // Vault (enterprise) namespace, optional
	backend   string // KV v2 mount, e.g. "secret"
	prefix    string // path prefix under the mount, e.g. "zfs-localpv"
}

var _ = RegisterProvider(Provider{
	UniqueID:    ProviderVault,
	Initializer: newVaultKMS,
})

func newVaultKMS(args ProviderInitArgs) (KeyStore, error) {
	cfg := args.Config
	addr := cfgString(cfg, cfgVaultAddress, "")
	if addr == "" {
		return nil, fmt.Errorf("kms(%s): missing %q", ProviderVault, cfgVaultAddress)
	}

	skipVerify := cfgBool(cfg, cfgVaultSkipVerify, false)
	if skipVerify {
		klog.Warningf("kms(%s): %s=true — TLS server verification is DISABLED for the KMS that holds your encryption keys; this exposes keys to MITM and must not be used in production",
			ProviderVault, cfgVaultSkipVerify)
	}
	tlsCfg := &tls.Config{InsecureSkipVerify: skipVerify} //nolint:gosec // opt-in
	if caPEM := cfgString(cfg, cfgVaultCACert, ""); caPEM != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(caPEM)) {
			return nil, fmt.Errorf("kms(%s): invalid %q PEM", ProviderVault, cfgVaultCACert)
		}
		tlsCfg.RootCAs = pool
	}
	// Optional client certificate for mTLS auth (e.g. OVHcloud OKMS).
	clientCert, err := loadClientCert(args)
	if err != nil {
		return nil, err
	}
	if clientCert != nil {
		tlsCfg.Certificates = []tls.Certificate{*clientCert}
	}

	k := &vaultKMS{
		httpc: &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		},
		addr:      strings.TrimRight(addr, "/"),
		namespace: cfgString(cfg, cfgVaultNamespace, ""),
		backend:   cfgString(cfg, cfgVaultBackendPath, "secret"),
		prefix:    cfgString(cfg, cfgVaultKeyPrefix, "zfs-localpv"),
	}

	token, err := k.authenticate(args)
	if err != nil {
		return nil, err
	}
	k.token = token
	return k, nil
}

func (k *vaultKMS) authenticate(args ProviderInitArgs) (string, error) {
	switch method := cfgString(args.Config, cfgVaultAuthMethod, vaultAuthToken); method {
	case vaultAuthToken:
		return k.resolveToken(args)
	case vaultAuthKubernetes:
		return k.kubernetesLogin(args.Config)
	case vaultAuthCert:
		// Stock HashiCorp Vault TLS-certificate auth: present the client cert and
		// exchange it at auth/<path>/login for a client token.
		return k.certLogin(args.Config)
	case vaultAuthMTLS:
		// The mutual-TLS handshake IS the authentication (e.g. OVHcloud OKMS):
		// the KV endpoints accept the client cert directly — no login, no token.
		if !k.hasClientCert() {
			return "", fmt.Errorf("kms(%s): %s=%q requires a client certificate (%q or %q)",
				ProviderVault, cfgVaultAuthMethod, vaultAuthMTLS, cfgVaultClientCertSecretName, cfgVaultClientCert)
		}
		return "", nil
	default:
		return "", fmt.Errorf("kms(%s): unsupported %s %q", ProviderVault, cfgVaultAuthMethod, method)
	}
}

// hasClientCert reports whether a client certificate was loaded into the TLS
// config for mutual-TLS authentication.
func (k *vaultKMS) hasClientCert() bool {
	tr, ok := k.httpc.Transport.(*http.Transport)
	return ok && tr.TLSClientConfig != nil && len(tr.TLSClientConfig.Certificates) > 0
}

// certLogin performs stock Vault TLS-certificate auth: it POSTs to
// auth/<path>/login (default path "cert") with the client cert presented at the
// TLS layer, and returns the issued client token. An optional vaultRole selects
// a specific cert role ("name").
func (k *vaultKMS) certLogin(cfg map[string]interface{}) (string, error) {
	if !k.hasClientCert() {
		return "", fmt.Errorf("kms(%s): %s=%q requires a client certificate (%q or %q)",
			ProviderVault, cfgVaultAuthMethod, vaultAuthCert, cfgVaultClientCertSecretName, cfgVaultClientCert)
	}
	authPath := cfgString(cfg, cfgVaultAuthPath, "cert")
	path := fmt.Sprintf("/v1/auth/%s/login", strings.Trim(authPath, "/"))
	body := map[string]interface{}{}
	if role := cfgString(cfg, cfgVaultRole, ""); role != "" {
		body["name"] = role
	}
	ctx, cancel := context.WithTimeout(context.Background(), authRetryBudget)
	defer cancel()
	code, respBody, err := k.request(ctx, http.MethodPost, path, body)
	if err != nil {
		return "", err
	}
	if code != http.StatusOK {
		return "", fmt.Errorf("kms(%s): cert login failed (%d): %s", ProviderVault, code, string(respBody))
	}
	var resp struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return "", fmt.Errorf("kms(%s): decode cert login response: %w", ProviderVault, err)
	}
	if resp.Auth.ClientToken == "" {
		return "", fmt.Errorf("kms(%s): cert login returned empty token", ProviderVault)
	}
	return resp.Auth.ClientToken, nil
}

// loadClientCert builds the client certificate used for mTLS auth, from an
// inline PEM pair in the config or (preferred) a kubernetes.io/tls Secret named
// by vaultClientCertSecretName. Returns nil when no client cert is configured.
func loadClientCert(args ProviderInitArgs) (*tls.Certificate, error) {
	cfg := args.Config
	if certPEM := cfgString(cfg, cfgVaultClientCert, ""); certPEM != "" {
		keyPEM := cfgString(cfg, cfgVaultClientKey, "")
		if keyPEM == "" {
			return nil, fmt.Errorf("kms(%s): %q given without %q", ProviderVault, cfgVaultClientCert, cfgVaultClientKey)
		}
		cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
		if err != nil {
			return nil, fmt.Errorf("kms(%s): invalid client cert/key PEM: %w", ProviderVault, err)
		}
		return &cert, nil
	}

	secretName := cfgString(cfg, cfgVaultClientCertSecretName, "")
	if secretName == "" {
		return nil, nil
	}
	if args.KubeClient == nil {
		return nil, fmt.Errorf("kms(%s): nil kube client for client-cert secret", ProviderVault)
	}
	s, err := args.KubeClient.CoreV1().Secrets(args.Namespace).Get(
		context.Background(), secretName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("kms(%s): get client-cert secret %s/%s: %w",
			ProviderVault, args.Namespace, secretName, err)
	}
	certPEM, keyPEM := s.Data[tlsCertKey], s.Data[tlsKeyKey]
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return nil, fmt.Errorf("kms(%s): secret %s/%s must contain %q and %q",
			ProviderVault, args.Namespace, secretName, tlsCertKey, tlsKeyKey)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("kms(%s): invalid client cert/key in secret %s/%s: %w",
			ProviderVault, args.Namespace, secretName, err)
	}
	return &cert, nil
}

func (k *vaultKMS) resolveToken(args ProviderInitArgs) (string, error) {
	if tok := cfgString(args.Config, cfgVaultToken, ""); tok != "" {
		klog.Warningf("kms(%s): a Vault token is configured inline via %q in the %s ConfigMap, which is stored unencrypted and readable by anyone with 'get configmaps'; prefer %q to keep the token in a Secret",
			ProviderVault, cfgVaultToken, DefaultKMSConfigMapName, cfgVaultTokenSecretName)
		return tok, nil
	}
	if secretName := cfgString(args.Config, cfgVaultTokenSecretName, ""); secretName != "" {
		if args.KubeClient == nil {
			return "", fmt.Errorf("kms(%s): nil kube client for token secret", ProviderVault)
		}
		s, err := args.KubeClient.CoreV1().Secrets(args.Namespace).Get(
			context.Background(), secretName, metav1.GetOptions{})
		if err != nil {
			return "", fmt.Errorf("kms(%s): get token secret %s/%s: %w",
				ProviderVault, args.Namespace, secretName, err)
		}
		if tok := string(s.Data[vaultTokenSecretKey]); tok != "" {
			return tok, nil
		}
		return "", fmt.Errorf("kms(%s): secret %s/%s has no %q",
			ProviderVault, args.Namespace, secretName, vaultTokenSecretKey)
	}
	if tok := os.Getenv("VAULT_TOKEN"); tok != "" {
		return tok, nil
	}
	return "", fmt.Errorf("kms(%s): no token configured", ProviderVault)
}

func (k *vaultKMS) kubernetesLogin(cfg map[string]interface{}) (string, error) {
	role := cfgString(cfg, cfgVaultRole, "")
	if role == "" {
		return "", fmt.Errorf("kms(%s): missing %q for kubernetes auth", ProviderVault, cfgVaultRole)
	}
	jwt, err := os.ReadFile(saTokenPath)
	if err != nil {
		return "", fmt.Errorf("kms(%s): read service account token: %w", ProviderVault, err)
	}
	authPath := cfgString(cfg, cfgVaultAuthPath, vaultAuthKubernetes)
	path := fmt.Sprintf("/v1/auth/%s/login", strings.Trim(authPath, "/"))

	ctx, cancel := context.WithTimeout(context.Background(), authRetryBudget)
	defer cancel()
	code, body, err := k.request(ctx, http.MethodPost, path, map[string]interface{}{
		"role": role,
		"jwt":  strings.TrimSpace(string(jwt)),
	})
	if err != nil {
		return "", err
	}
	if code != http.StatusOK {
		return "", fmt.Errorf("kms(%s): kubernetes login failed (%d): %s", ProviderVault, code, string(body))
	}
	var resp struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("kms(%s): decode login response: %w", ProviderVault, err)
	}
	if resp.Auth.ClientToken == "" {
		return "", fmt.Errorf("kms(%s): kubernetes login returned empty token", ProviderVault)
	}
	return resp.Auth.ClientToken, nil
}

// dataPath / metaPath build the KV v2 data and metadata paths for a volume.
func (k *vaultKMS) dataPath(volumeID string) string {
	return k.kvPath("data", volumeID)
}

func (k *vaultKMS) metaPath(volumeID string) string {
	return k.kvPath("metadata", volumeID)
}

func (k *vaultKMS) kvPath(kind, volumeID string) string {
	segs := []string{"v1", k.backend, kind}
	if k.prefix != "" {
		segs = append(segs, strings.Trim(k.prefix, "/"))
	}
	segs = append(segs, volumeID)
	return "/" + strings.Join(segs, "/")
}

func (k *vaultKMS) request(ctx context.Context, method, path string, body interface{}) (int, []byte, error) {
	var payload []byte
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		payload = b
	}

	for attempt := 0; ; attempt++ {
		var reader io.Reader
		if payload != nil {
			reader = bytes.NewReader(payload)
		}
		req, err := http.NewRequestWithContext(ctx, method, k.addr+path, reader)
		if err != nil {
			return 0, nil, err
		}
		if k.token != "" {
			req.Header.Set("X-Vault-Token", k.token)
		}
		if k.namespace != "" {
			req.Header.Set("X-Vault-Namespace", k.namespace)
		}
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := k.httpc.Do(req)
		if err != nil {
			return 0, nil, fmt.Errorf("kms(%s): %s %s: %w", ProviderVault, method, path, err)
		}
		data, rerr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if rerr != nil {
			return resp.StatusCode, nil, rerr
		}

		// Back off and retry on rate-limit / transient-unavailable responses. Once
		// the attempt budget is spent, return the last response so the caller
		// surfaces the backend's own error rather than looping forever.
		//
		// Retrying is safe for every method we issue: a KV v2 data write (POST)
		// that actually committed before a 503 just adds another version with the
		// same key value, which GetOrCreateKey's read-back then confirms; the
		// metadata DELETE is idempotent (a 404 is accepted); and an auth login
		// re-issued after a lost response only mints a fresh (short-lived) token.
		if (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable) &&
			attempt < vaultRetryMaxAttempts {
			wait := retryAfter(resp.Header, attempt)
			klog.V(4).Infof("kms(%s): %s %s got %d, backing off %s (attempt %d/%d)",
				ProviderVault, method, path, resp.StatusCode, wait, attempt+1, vaultRetryMaxAttempts)
			select {
			case <-ctx.Done():
				return 0, nil, ctx.Err()
			case <-time.After(wait):
			}
			continue
		}
		return resp.StatusCode, data, nil
	}
}

// retryAfter returns how long to wait before the next attempt. It honors a
// numeric Retry-After header when the backend sends one (capped so an absurd
// value can't stall provisioning), otherwise it uses capped exponential backoff
// with equal jitter to avoid a thundering herd of concurrent CreateVolume calls
// all retrying in lockstep.
func retryAfter(h http.Header, attempt int) time.Duration {
	if v := h.Get("Retry-After"); v != "" {
		if secs, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && secs > 0 {
			d := time.Duration(secs) * time.Second
			if max := 4 * vaultRetryMax; d > max {
				d = max
			}
			return d
		}
	}
	backoff := vaultRetryBase << attempt
	if backoff > vaultRetryMax {
		backoff = vaultRetryMax
	}
	half := backoff / 2
	return half + time.Duration(rand.Int63n(int64(half)+1))
}

func (k *vaultKMS) FetchKey(ctx context.Context, volumeID string) (string, error) {
	code, body, err := k.request(ctx, http.MethodGet, k.dataPath(volumeID), nil)
	if err != nil {
		return "", err
	}
	if code == http.StatusNotFound {
		return "", errKeyNotFound
	}
	if code != http.StatusOK {
		return "", fmt.Errorf("kms(%s): read %s failed (%d): %s", ProviderVault, volumeID, code, string(body))
	}
	var resp struct {
		Data struct {
			Data map[string]string `json:"data"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("kms(%s): decode read response: %w", ProviderVault, err)
	}
	key := resp.Data.Data[vaultDataKey]
	if err := ValidateHexKey(key); err != nil {
		return "", fmt.Errorf("kms(%s): stored key for %s: %w", ProviderVault, volumeID, err)
	}
	return key, nil
}

func (k *vaultKMS) GetOrCreateKey(ctx context.Context, volumeID string) (string, error) {
	key, err := k.FetchKey(ctx, volumeID)
	if err == nil {
		return key, nil
	}
	if !errors.Is(err, errKeyNotFound) {
		return "", err
	}

	key, err = GenerateHexKey()
	if err != nil {
		return "", err
	}
	payload := map[string]interface{}{
		"data": map[string]string{vaultDataKey: key},
	}
	code, body, err := k.request(ctx, http.MethodPost, k.dataPath(volumeID), payload)
	if err != nil {
		return "", err
	}
	if code != http.StatusOK && code != http.StatusNoContent {
		return "", fmt.Errorf("kms(%s): store %s failed (%d): %s", ProviderVault, volumeID, code, string(body))
	}

	// Confirm the freshly stored key is actually readable before returning, so the
	// node never fails to load-key on a backend with read-after-write lag (see
	// writeReadbackTimeout). Strongly consistent backends succeed on the first
	// read and return immediately.
	deadline := time.Now().Add(writeReadbackTimeout)
	for {
		got, ferr := k.FetchKey(ctx, volumeID)
		if ferr == nil && got == key {
			return key, nil
		}
		if ferr != nil && !errors.Is(ferr, errKeyNotFound) {
			return "", ferr
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("kms(%s): key for %s not readable within %s after store (backend read-after-write lag)",
				ProviderVault, volumeID, writeReadbackTimeout)
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(writeReadbackInterval):
		}
	}
}

func (k *vaultKMS) RemoveKey(ctx context.Context, volumeID string) error {
	// Delete the metadata path to remove all versions (KV v2).
	code, body, err := k.request(ctx, http.MethodDelete, k.metaPath(volumeID), nil)
	if err != nil {
		return err
	}
	if code != http.StatusOK && code != http.StatusNoContent && code != http.StatusNotFound {
		return fmt.Errorf("kms(%s): delete %s failed (%d): %s", ProviderVault, volumeID, code, string(body))
	}
	return nil
}

func (k *vaultKMS) Destroy() {}

// ensure vaultKMS satisfies KeyStore.
var _ KeyStore = (*vaultKMS)(nil)
