# Volume Encryption

zfs-localpv supports [ZFS native encryption](https://openzfs.github.io/openzfs-docs/man/master/8/zfs-load-key.8.html)
per PersistentVolume. Two families are available:

- **StorageClass-level key (legacy)** — one static key for all volumes of a
  StorageClass, via a `keylocation` file present on every node. See the
  `encryption`, `keyformat`, `keylocation` parameters in
  [storageclasses.md](./storageclasses.md).
- **Per-volume key** — each PV gets its own key, sourced either from a Kubernetes
  Secret referenced by the PVC (bring your own key), or generated automatically
  by the driver and stored in a managed Secret.

With per-volume keys, the key material (a 32-byte key encoded as 64 hex
characters) is **never stored in the ZFSVolume CR or on the node disk**, and is
fed to `zfs create` / `zfs load-key` over stdin. The key is kept in a Kubernetes
Secret, typically in **etcd** (base64, plaintext unless etcd encryption-at-rest is
enabled). See *Security notes*. The dataset is created with `keylocation=prompt`,
so the node reloads the key at mount time (via `zfs load-key`), which lets
encrypted volumes survive node reboots.

Encrypted volumes carry `openebs.io/encrypted: "true"` in the PV's
`spec.csi.volumeAttributes` (a boolean marker — never the key), so you can tell a
PV is encrypted without inspecting the `ZFSVolume` CR:
`kubectl get pv <name> -o jsonpath='{.spec.csi.volumeAttributes.openebs\.io/encrypted}'`.
The authoritative source remains the `ZFSVolume` CR (`spec.encryption`,
`spec.encryptionKeyRef`).

## Prerequisites

- A ZFS pool that supports encryption (OpenZFS >= 0.8).
- The external-provisioner runs with `--extra-create-metadata=true` (default in
  the shipped manifests) so the controller learns the PVC name/namespace.
- RBAC (already included in the Helm chart / operator YAML): the controller and
  node components can `get` Secrets cluster-wide (the referenced Secret can live
  in any PVC namespace); auto mode additionally lets the controller
  `create`/`update` Secrets, granted **namespaced** to the driver namespace only
  (deletion is handled by Kubernetes garbage collection, so no `delete` grant is
  needed).

---

## Key from a Kubernetes Secret (per PVC)

The user brings their own key. The PVC references a Secret in its own namespace
via an annotation.

```yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: openebs-zfspv-encrypted
parameters:
  poolname: "zfspv-pool"
  fstype: "ext4"
  encryption: "aes-256-gcm"
provisioner: zfs.csi.openebs.io
```

Create the key Secret (64 hex chars = 32 bytes) in the PVC namespace:

```bash
kubectl create secret generic csi-encryption-key \
  --from-literal=key="$(openssl rand -hex 32)"
```

Reference it from the PVC:

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: csi-zfspv-encrypted
  annotations:
    local.zfs.openebs.io/encryption-secret: "csi-encryption-key"
spec:
  storageClassName: openebs-zfspv-encrypted
  accessModes: ["ReadWriteOnce"]
  resources:
    requests:
      storage: 4Gi
```

Notes:
- The Secret must be in the **same namespace** as the PVC.
- The Secret data key is `key`; the value must be 64 hex characters.
- Deleting the PV does **not** delete your Secret.

If the annotation references a Secret that is missing or does not contain a valid
64-char hex key, provisioning fails immediately with a clear `InvalidArgument`
error rather than deferring the failure to the node. Likewise, if a key stops
matching its dataset (an altered Secret, or a wrong key), `zfs load-key` is
rejected and the mount fails with a clear "encryption key … is incorrect … may
have been changed" error rather than silently mounting nothing.

Full example: [`deploy/sample/encrypted-pvc.yaml`](../deploy/sample/encrypted-pvc.yaml).

---

## Auto-generated key (driver-managed)

For zero-configuration per-volume encryption, the driver can generate the key
itself and store it in a Secret it manages, in the OpenEBS namespace. This is the
recommended mode for operators and StatefulSets that create PVCs on their own
(via `volumeClaimTemplates`): each PVC gets its own unique key with **nothing to
configure per PVC**.

Opt in on the StorageClass with `autoCreateEncryptionKey: "true"`:

```yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: openebs-zfspv-encrypted-auto
parameters:
  poolname: "zfspv-pool"
  fstype: "ext4"
  encryption: "aes-256-gcm"
  autoCreateEncryptionKey: "true"
provisioner: zfs.csi.openebs.io
```

A StatefulSet then just references the StorageClass — every replica's PVC gets
its own key:

```yaml
  volumeClaimTemplates:
    - metadata: { name: data }
      spec:
        storageClassName: openebs-zfspv-encrypted-auto
        accessModes: ["ReadWriteOnce"]
        resources: { requests: { storage: 10Gi } }
```

Behaviour:
- At CreateVolume the driver generates a 32-byte hex key and stores it in a
  Secret named `zfs-enc-<volume-id>` in the OpenEBS namespace, labelled
  `local.zfs.openebs.io/auto-managed=true`. The generation is idempotent across
  CreateVolume retries.
- The Secret is **garbage-collected automatically** when the volume is deleted,
  via an OwnerReference to its ZFSVolume CR.

**Security trade-off:** the key is stored at rest in a Kubernetes Secret (typically in etcd, base64-encoded). Enable
[etcd encryption at rest](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/)
if this matters for your threat model.

The managed Secret is the only copy of the generated key, so it is protected two
ways: **`immutable: true`** (blocks an accidental `kubectl edit`/patch that would
silently corrupt the key and make the volume unmountable) and an
**OwnerReference** to its ZFSVolume CR, which makes the Kubernetes garbage
collector reap the Secret automatically on every volume-deletion path (normal
teardown and out-of-band CR deletion alike) — no finalizer, and no explicit
delete. Do **not** manually `kubectl delete` the `zfs-enc-<volume>` Secret while
its PVC exists: it is the sole copy of the key, and removing it makes the volume
permanently unmountable.

The two per-volume modes are evaluated in precedence order, so a **single
StorageClass can serve both "bring your own key" and "auto" users**: the PVC
annotation (Secret mode) takes precedence, else `autoCreateEncryptionKey: "true"`
auto-generates a key. A developer who sets the annotation overrides the auto
behaviour for their PVC. If the annotation references a missing or invalid
Secret, provisioning fails immediately (it does **not** silently fall back to
auto-generation).

Full example: [`deploy/sample/encrypted-pvc-auto.yaml`](../deploy/sample/encrypted-pvc-auto.yaml).

---

## Key rotation (manual)

Automated rotation is intentionally **not** performed by the driver: there is no
standard CSI trigger for it, and an interrupted rotation can make data
unrecoverable. Rotate manually per volume on the owning node:

```bash
# 1. Generate the new key and ensure the current key is loaded.
NEWKEY=$(openssl rand -hex 32)
zfs load-key <pool>/<pv-name>        # feed the current key on stdin

# 2. Update the Secret first, then re-wrap with the new value.
kubectl -n <ns> patch secret <name> -p '{"stringData":{"key":"'"$NEWKEY"'"}}'
printf '%s' "$NEWKEY" | zfs change-key -o keyformat=hex -o keylocation=prompt <pool>/<pv-name>
```

`zfs change-key` re-wraps the dataset master key; existing data is not
re-encrypted. Update the Secret **before** running `change-key` so a crash
between the two steps leaves a recoverable state.

---

## Security notes

- Key material is never written to the ZFSVolume CR or the node disk, and is fed
  to `zfs` over stdin. **The key is stored in a Kubernetes Secret, typically in etcd**
  (base64) — enable
  [etcd encryption at rest](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/)
  when key custody matters.
- gRPC request/response logging strips secrets, and the key is passed to `zfs`
  on stdin, so it never appears in process arguments or logs.
- The controller and node are granted cluster-wide `get` (not `list`) on Secrets
  because a referenced Secret can live in any PVC namespace. Auto-mode
  `create`/`update` on Secrets is granted **namespaced** to the driver namespace
  only (`openebs-zfs-provisioner-secrets-role`), not cluster-wide; no `delete`
  grant is needed since the Secret is garbage-collected via its OwnerReference.

## Limitations

- The managed per-volume key is always `hex` (a 32-byte key as 64 hex chars).
  The legacy StorageClass `keyformat` (`passphrase`/`raw`/`hex`) is unaffected.
- Key rotation is manual (see above) — the driver performs no automatic rotation
  for either the per-volume or the legacy StorageClass encryption.

The legacy `keylocation`-file StorageClass encryption continues to work unchanged
alongside per-volume keys.
