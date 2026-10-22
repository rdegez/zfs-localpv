/*
Copyright 2020 The OpenEBS Authors.

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

package driver

import (
	"testing"

	"github.com/stretchr/testify/assert"

	zfsapi "github.com/openebs/zfs-localpv/v2/pkg/apis/openebs.io/zfs/v1"
	"github.com/openebs/zfs-localpv/v2/pkg/zfs"
)

func TestRoundOff(t *testing.T) {

	tests := map[string]struct {
		input    int64
		expected int64
	}{
		"Minimum allocatable is 1Mi": {input: 1, expected: Mi},
		"roundOff to same Mi size":   {input: Mi, expected: Mi},
		"roundOff to nearest Mi":     {input: Mi + 1, expected: Mi * 2},
		"roundOff to same Gi size":   {input: Gi, expected: Gi},
		"roundOff to nearest Gi":     {input: Gi + 1, expected: Gi * 2},
		"roundOff MB size":           {input: 5 * MB, expected: 5 * Mi},
		"roundOff GB size":           {input: 5 * GB, expected: 5 * Gi},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, test.expected, getRoundedCapacity(test.input))
		})
	}
}

func TestPVCEncryptionSecretName(t *testing.T) {
	key := zfs.PVCEncryptionSecretAnnotation
	tests := map[string]struct {
		annotations map[string]string
		want        string
		wantErr     bool
	}{
		"no annotations":                {annotations: nil},
		"annotation not set":            {annotations: map[string]string{"other": "x"}},
		"annotation set":                {annotations: map[string]string{key: "db-key"}, want: "db-key"},
		"annotation set but empty":      {annotations: map[string]string{key: ""}, wantErr: true},
		"annotation set to whitespaces": {annotations: map[string]string{key: "  "}, wantErr: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := pvcEncryptionSecretName(test.annotations)
			if test.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, test.want, got)
		})
	}
}

func TestCloneKeyConflict(t *testing.T) {
	key := zfs.PVCEncryptionSecretAnnotation
	src := &zfsapi.EncryptionKeyReference{Name: "abc", Namespace: "apps"}
	tests := map[string]struct {
		src         *zfsapi.EncryptionKeyReference
		annotations map[string]string
		wantErr     bool
	}{
		"no annotation":                                        {src: src},
		"annotation naming the source's key":                   {src: src, annotations: map[string]string{key: "abc"}},
		"annotation naming another key":                        {src: src, annotations: map[string]string{key: "def"}, wantErr: true},
		"empty annotation":                                     {src: src, annotations: map[string]string{key: ""}, wantErr: true},
		"annotation on a clone of a non-per-volume-key source": {annotations: map[string]string{key: "abc"}, wantErr: true},
		"no annotation, source without per-volume key":         {},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := cloneKeyConflict(test.src, test.annotations, "apps")
			if test.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
