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
	"strings"
	"testing"

	apis "github.com/openebs/zfs-localpv/pkg/apis/openebs.io/zfs/v1"
)

func hasArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

func TestUsesManagedKey(t *testing.T) {
	tests := []struct {
		name string
		vol  apis.VolumeInfo
		want bool
	}{
		{"secret ref", apis.VolumeInfo{EncryptionKeyRef: &apis.EncryptionKeyReference{Name: "k"}}, true},
		{"legacy keylocation", apis.VolumeInfo{KeyLocation: "file:///etc/key"}, false},
		{"none", apis.VolumeInfo{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vol := &apis.ZFSVolume{Spec: tt.vol}
			if got := UsesManagedKey(vol); got != tt.want {
				t.Errorf("UsesManagedKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBuildCreateArgs_ManagedKey(t *testing.T) {
	base := func() *apis.ZFSVolume {
		v := &apis.ZFSVolume{}
		v.Name = "pvc-1"
		v.Spec.PoolName = "pool"
		v.Spec.Capacity = "1073741824"
		v.Spec.Encryption = "aes-256-gcm"
		v.Spec.KeyFormat = "hex"
		return v
	}

	t.Run("zvol with secret ref uses keylocation=prompt", func(t *testing.T) {
		v := base()
		v.Spec.EncryptionKeyRef = &apis.EncryptionKeyReference{Name: "my-key", Namespace: "app"}
		args := buildZvolCreateArgs(v)
		if !hasArg(args, "keylocation=prompt") {
			t.Errorf("expected keylocation=prompt, got %v", args)
		}
		if !hasArg(args, "encryption=aes-256-gcm") || !hasArg(args, "keyformat=hex") {
			t.Errorf("expected encryption/keyformat args, got %v", args)
		}
		for _, a := range args {
			if strings.HasPrefix(a, "keylocation=file") {
				t.Errorf("managed key must not use a keylocation file, got %v", args)
			}
		}
	})

	t.Run("dataset with secret ref uses keylocation=prompt", func(t *testing.T) {
		v := base()
		v.Spec.VolumeType = VolTypeDataset
		v.Spec.EncryptionKeyRef = &apis.EncryptionKeyReference{Name: "my-key"}
		args := buildDatasetCreateArgs(v)
		if !hasArg(args, "keylocation=prompt") {
			t.Errorf("expected keylocation=prompt, got %v", args)
		}
	})

	t.Run("legacy keylocation file is preserved", func(t *testing.T) {
		v := base()
		v.Spec.KeyLocation = "file:///etc/zfs/key"
		args := buildZvolCreateArgs(v)
		if !hasArg(args, "keylocation=file:///etc/zfs/key") {
			t.Errorf("expected legacy keylocation file, got %v", args)
		}
		if hasArg(args, "keylocation=prompt") {
			t.Errorf("legacy mode must not use prompt, got %v", args)
		}
	})
}

func TestBuildVolumeRestoreArgs_Encryption(t *testing.T) {
	rstr := &apis.ZFSRestore{}
	rstr.Spec.RestoreSrc = "10.0.0.1:9000"
	rstr.Spec.VolumeName = "pvc-restore"
	rstr.VolSpec.PoolName = "pool"
	rstr.VolSpec.Encryption = "aes-256-gcm"
	rstr.VolSpec.KeyFormat = "hex"

	t.Run("managed key uses provided temp keylocation", func(t *testing.T) {
		rstr.VolSpec.EncryptionKeyRef = &apis.EncryptionKeyReference{Name: "my-key"}
		_, recvArgs, err := buildVolumeRestoreArgs(rstr, "file:///tmp/zfs-enc-key-123")
		if err != nil {
			t.Fatalf("buildVolumeRestoreArgs: %v", err)
		}
		if !hasArg(recvArgs, "keylocation=file:///tmp/zfs-enc-key-123") {
			t.Errorf("expected temp keylocation, got %v", recvArgs)
		}
		if !hasArg(recvArgs, "encryption=aes-256-gcm") || !hasArg(recvArgs, "keyformat=hex") {
			t.Errorf("expected encryption/keyformat, got %v", recvArgs)
		}
	})

	t.Run("no override falls back to VolSpec.KeyLocation", func(t *testing.T) {
		rstr.VolSpec.EncryptionKeyRef = nil
		rstr.VolSpec.KeyLocation = "file:///etc/zfs/key"
		_, recvArgs, err := buildVolumeRestoreArgs(rstr, "")
		if err != nil {
			t.Fatalf("buildVolumeRestoreArgs: %v", err)
		}
		if !hasArg(recvArgs, "keylocation=file:///etc/zfs/key") {
			t.Errorf("expected legacy keylocation, got %v", recvArgs)
		}
	})
}
