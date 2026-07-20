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
  in any PVC namespace); for the auto mode, the node agent can also
  `create`/`delete` Secrets, granted **namespaced** to the driver namespace only.

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

Behaviour — the key lives exactly as long as the data:
- The node agent generates a 32-byte hex key right before `zfs create` and stores
  it in an immutable Secret named `zfs-enc-<volume-id>` in the OpenEBS namespace,
  labelled `local.zfs.openebs.io/auto-managed=true`. The Secret holds the key
  under `key`, as in the Secret mode, and the volume name under `volume` (used to
  back the key up, see below). The generation is idempotent across retries, and a
  pre-existing Secret of that name without the label is never adopted.
- The node agent deletes the Secret only after `zfs destroy` succeeded. A
  provisioning that fails before the dataset exists leaves no Secret behind.
- Deleting a ZFSVolume **without** destroying its dataset (removing its
  `zfs.openebs.io/finalizer` first, see
  [import-existing-volume.md](./import-existing-volume.md)) keeps the key, so the
  dataset can be imported again later.
- A clone shares its parent's Secret: it never creates nor deletes it.

**Security trade-off:** the key is stored at rest in a Kubernetes Secret (typically in etcd, base64-encoded). Enable
[etcd encryption at rest](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/)
if this matters for your threat model.

### Protecting the generated keys

The managed Secret is the only copy of the generated key (unless you back it up
to a KMS, see below), so it is protected two ways:

- **`immutable: true`** blocks an accidental `kubectl edit`/patch that would
  silently corrupt the key and make the volume unmountable.
- A **ValidatingAdmissionPolicy** shipped with the Helm chart (Kubernetes >= 1.30,
  `encryptionKeyProtection.enabled`, on by default) denies the deletion of these
  Secrets to everyone, cluster-admin included, except the node agent's service
  account, and denies removing their `local.zfs.openebs.io/auto-managed` label,
  which would bypass the policy. Deleting the driver namespace therefore fails to
  remove them as long as the policy is in place. The policy guards against
  mistakes; it is not a security boundary against cluster administrators, who
  can lift it.

To delete such a Secret anyway (break-glass, for instance after destroying a
dataset by hand), annotate it first:

```bash
kubectl -n openebs annotate secret zfs-enc-<volume-id> local.zfs.openebs.io/allow-key-deletion=true
kubectl -n openebs delete secret zfs-enc-<volume-id>
```

The policy is not part of the operator YAML (`deploy/zfs-operator.yaml`); when
installing with it, apply the two objects rendered by the chart template
`encryption-key-protection.yaml`, adjusting the namespace and the node service
account name.

The two per-volume modes are evaluated in precedence order, so a **single
StorageClass can serve both "bring your own key" and "auto" users**: the PVC
annotation (Secret mode) takes precedence, else `autoCreateEncryptionKey: "true"`
auto-generates a key. A developer who sets the annotation overrides the auto
behaviour for their PVC. If the annotation references a missing or invalid
Secret, provisioning fails immediately (it does **not** silently fall back to
auto-generation).

Full example: [`deploy/sample/encrypted-pvc-auto.yaml`](../deploy/sample/encrypted-pvc-auto.yaml).

---

## Keeping keys in an external KMS (External Secrets Operator)

The driver only reads keys from Kubernetes Secrets. To keep the source of truth,
or a copy, of the keys in an external KMS (HashiCorp Vault, OpenBao, a cloud KMS,
…), use the [External Secrets Operator](https://external-secrets.io/) (ESO).

**Pull — the key lives in the KMS (Secret mode).** An `ExternalSecret`
materialises the key as the Secret referenced by the PVC annotation. It must
exist before the PVC is created, and its value must never change while the
volume exists, so sync it once:

```yaml
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: db-0-key
  namespace: apps
spec:
  refreshPolicy: CreatedOnce
  secretStoreRef: { kind: ClusterSecretStore, name: vault }
  target:
    name: db-0-key            # referenced by local.zfs.openebs.io/encryption-secret
    creationPolicy: Owner
  data:
    - secretKey: key
      remoteRef: { key: zfs/apps/db-0, property: key }
```

With `creationPolicy: Owner`, deleting the `ExternalSecret` deletes the Secret;
the key itself stays in the KMS.

**Push — back up the generated keys to the KMS (auto mode, key escrow).** A
single `PushSecret` in the driver namespace selects the driver-managed Secrets by
label and copies each key to its own KMS entry, named after its volume
(`zfs-localpv/<volume-id>` below). ESO applies the same remote reference to every
Secret a label selector matches, so the template builds a per-volume entry from
the `volume` and `key` data of each Secret, and `dataTo` pushes it; the Secrets
themselves are not modified. With `deletionPolicy: None`, the copy stays in the
KMS after the volume, and thus its Secret, is deleted. Example for a Vault KV v2
store:

> **Warning:** do not use `deletionPolicy: Delete` with a label selector. As of
> ESO 2.12, each reconcile deletes the KMS entries pushed for the other Secrets
> the selector matches, so only one key is kept in the KMS at a time
> ([external-secrets#7123](https://github.com/external-secrets/external-secrets/issues/7123)).

```yaml
apiVersion: external-secrets.io/v1alpha1
kind: PushSecret
metadata:
  name: zfs-encryption-keys
  namespace: openebs
spec:
  refreshInterval: 1m
  deletionPolicy: None
  secretStoreRefs:
    - { kind: ClusterSecretStore, name: vault }
  selector:
    secret:
      selector:
        matchLabels:
          local.zfs.openebs.io/auto-managed: "true"
  template:
    templateFrom:
      - target: Data
        literal: |
          backup-{{ .volume }}: '{"key":"{{ .key }}"}'
  dataTo:
    - storeRef: { kind: ClusterSecretStore, name: vault }
      match: { regexp: "^backup-" }
      rewrite:
        - regexp: { source: "^backup-(.*)$", target: "zfs-localpv/$1" }
```

With a Vault store, each KMS entry then holds `{"key": "<64 hex>"}`. The layout
depends on the ESO provider: the OVHcloud provider, for instance, nests the
value under the generated entry name, `{"backup-<volume-id>": {"key": "<64 hex>"}}`
(property `backup-<volume-id>.key`). If a driver-managed Secret is lost while
its dataset still exists, recreate it from that copy with the same name, labels
and data (`key`, `volume`) before the volume is mounted again.

To keep the key material out of etcd, enable
[etcd encryption at rest with a KMS provider](https://kubernetes.io/docs/tasks/administer-cluster/kms-provider/).

---

## Snapshots and clones

Snapshots of an encrypted volume are encrypted with it. Clones, from a volume or
from a snapshot, inherit the parent's encryption root and key source: the node
loads the parent key before `zfs clone`, so cloning also works right after a node
reboot, and the clone loads the same key at mount.

## Backup and restore (Velero): not supported

Backup and restore of volumes that use a per-volume key are **not supported**. In
zfs-localpv, backup and restore are driven by the `ZFSBackup` / `ZFSRestore` CRs,
which the OpenEBS Velero plugin (`openebs/velero-plugin`) creates. Tested with
Velero 1.14 and velero-plugin 3.6.0:

- **Restore fails.** The plugin rebuilds the restored `ZFSVolume` from the saved
  object with its own copy of the zfs-localpv API types, which predates the
  per-volume key fields. The key source is dropped, so the driver has no key to
  hand to `zfs recv`, and the receive fails with `Cannot use 'prompt' keylocation
  because stdin is in use`.
- **Backups are not encrypted.** The backup path streams a non-raw `zfs send`,
  which ZFS decrypts on the fly: the data leaves the node and reaches the object
  store in clear text, and deleting a volume's key does not make its backups
  unreadable. This applies to the legacy StorageClass encryption too.

Supporting it needs changes outside this driver (an updated Velero plugin) and a
design for encrypted backups: a raw `zfs send -w` keeps the stream encrypted,
but restoring it requires the volume's original key, which the auto-generated
key mode deletes together with the volume unless it was backed up to a KMS (see
above). Until then, back up such volumes at the application level.

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
between the two steps leaves a recoverable state. The driver-managed Secrets of
the auto mode are immutable and are not meant to be rotated.

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
  because a referenced Secret can live in any PVC namespace. The auto mode's
  `create`/`delete` on Secrets is granted to the node agent only, **namespaced**
  to the driver namespace (`openebs-zfs-node-secrets-role`); the controller has
  no write access to Secrets. The node never deletes a Secret without the
  `local.zfs.openebs.io/auto-managed=true` label.

## Limitations

- The managed per-volume key is always `hex` (a 32-byte key as 64 hex chars).
  The legacy StorageClass `keyformat` (`passphrase`/`raw`/`hex`) is unaffected.
- Key rotation is manual (see above) — the driver performs no automatic rotation
  for either the per-volume or the legacy StorageClass encryption.
- **Backup and restore through Velero are not supported** — see *Backup and
  restore (Velero): not supported*.

The legacy `keylocation`-file StorageClass encryption continues to work unchanged
alongside per-volume keys.
