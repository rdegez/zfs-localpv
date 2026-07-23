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

// Package kms provides a small, pluggable abstraction over key management
// backends used to encrypt individual ZFS volumes. Each backend is a KeyStore
// that can hand back a per-volume key (hex encoded, 32 bytes / 64 chars) which
// is then supplied to ZFS native encryption (keyformat=hex, keylocation=prompt).
//
// The design is intentionally slimmed down from ceph-csi's internal/kms: ZFS
// performs its own key wrapping, so we only need a per-volume key store, not the
// DEK-wrapping machinery.
package kms

import (
	"context"
	"fmt"

	"k8s.io/client-go/kubernetes"
)

// KeyStore is implemented by every key management backend.
type KeyStore interface {
	// GetOrCreateKey returns the hex encoded key for volumeID, generating and
	// persisting a new one if the backend supports generation and none exists.
	// It is called on the controller at CreateVolume time.
	GetOrCreateKey(ctx context.Context, volumeID string) (string, error)

	// FetchKey returns the hex encoded key for volumeID. It is called on the
	// node at create and at load-key (mount) time and must not generate a key.
	FetchKey(ctx context.Context, volumeID string) (string, error)

	// RemoveKey deletes the key for volumeID. It is called on the controller at
	// DeleteVolume time. Backends that do not own the key material (e.g. a user
	// provided Secret) implement this as a no-op.
	RemoveKey(ctx context.Context, volumeID string) error

	// Destroy releases any resources held by the KeyStore (temp files, clients).
	Destroy()
}

// ProviderInitArgs carries everything a provider needs to build a KeyStore.
type ProviderInitArgs struct {
	// KMSID is the identifier of the selected configuration section (may be
	// empty for backends configured directly from the ZFSVolume spec).
	KMSID string
	// Config is the provider specific configuration (from the KMS ConfigMap or
	// synthesized from the ZFSVolume spec).
	Config map[string]interface{}
	// Namespace is the namespace to look up referenced Secrets/ConfigMaps in.
	Namespace string
	// KubeClient is a Kubernetes clientset for reading Secrets/ConfigMaps.
	KubeClient kubernetes.Interface
}

// ProviderInitFunc builds a KeyStore from the given args.
type ProviderInitFunc func(ProviderInitArgs) (KeyStore, error)

// Provider registers a KeyStore implementation under a unique type name.
type Provider struct {
	UniqueID    string
	Initializer ProviderInitFunc
}

// providers holds every registered backend, keyed by Provider.UniqueID.
var providers = map[string]Provider{}

// RegisterProvider adds a provider to the registry. It is meant to be called
// from a package level `var _ = RegisterProvider(...)` so the side effect runs
// on import. It panics on an invalid or duplicate registration.
func RegisterProvider(p Provider) bool {
	if p.UniqueID == "" {
		panic("kms: provider with empty UniqueID")
	}
	if p.Initializer == nil {
		panic(fmt.Sprintf("kms: provider %q has a nil Initializer", p.UniqueID))
	}
	if _, ok := providers[p.UniqueID]; ok {
		panic(fmt.Sprintf("kms: provider %q already registered", p.UniqueID))
	}
	providers[p.UniqueID] = p
	return true
}

// GetKMS returns a KeyStore for the provider named by providerType.
func GetKMS(providerType string, args ProviderInitArgs) (KeyStore, error) {
	p, ok := providers[providerType]
	if !ok {
		return nil, fmt.Errorf("kms: unknown provider %q", providerType)
	}
	return p.Initializer(args)
}
