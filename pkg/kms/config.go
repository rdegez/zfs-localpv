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
	"encoding/json"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	// DefaultKMSConfigMapName is the ConfigMap holding the KMS backend
	// configuration sections, keyed by kmsID. Each value is a JSON object
	// describing one backend (its "provider" and provider specific settings).
	DefaultKMSConfigMapName = "openebs-zfs-kms-config"

	// ConfigProviderKey is the field inside a config section naming the backend.
	ConfigProviderKey = "provider"
)

// LoadProviderConfig reads the KMS configuration section identified by kmsID
// from the given ConfigMap and returns the provider type and its config map.
func LoadProviderConfig(
	client kubernetes.Interface,
	namespace, configMapName, kmsID string,
) (string, map[string]interface{}, error) {
	cm, err := client.CoreV1().ConfigMaps(namespace).Get(
		context.Background(), configMapName, metav1.GetOptions{})
	if err != nil {
		return "", nil, fmt.Errorf("kms: get configmap %s/%s: %w", namespace, configMapName, err)
	}
	raw, ok := cm.Data[kmsID]
	if !ok {
		return "", nil, fmt.Errorf("kms: configmap %s/%s has no section for id %q",
			namespace, configMapName, kmsID)
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return "", nil, fmt.Errorf("kms: invalid JSON for id %q: %w", kmsID, err)
	}
	provider, _ := cfg[ConfigProviderKey].(string)
	if provider == "" {
		return "", nil, fmt.Errorf("kms: config for id %q is missing %q", kmsID, ConfigProviderKey)
	}
	return provider, cfg, nil
}

// cfgString returns the string value for key in config, or def if absent/empty.
func cfgString(config map[string]interface{}, key, def string) string {
	if v, ok := config[key].(string); ok && v != "" {
		return v
	}
	return def
}

// cfgBool returns the boolean value for key in config (accepts a real bool or
// the strings "true"/"false"), or def if absent.
func cfgBool(config map[string]interface{}, key string, def bool) bool {
	switch v := config[key].(type) {
	case bool:
		return v
	case string:
		return v == "true"
	default:
		return def
	}
}
