# Volume Encryption

zfs-localpv supports [ZFS native encryption](https://openzfs.github.io/openzfs-docs/man/master/8/zfs-load-key.8.html)
per PersistentVolume. Two families are available:

- **StorageClass-level key (legacy)** — one static key for all volumes of a
  StorageClass, via a `keylocation` file present on every node. See the
  `encryption`, `keyformat`, `keylocation` parameters in
  [storageclasses.md](./storageclasses.md).
- **Per-volume key** — each PV gets its own key, sourced from
  either a Kubernetes Secret referenced by the PVC, or a KMS backend
  (HashiCorp Vault). This document covers the per-volume modes (**Mode 1–3**
  below).

With per-volume keys, the key material (a 32-byte key encoded as 64 hex
characters) is **never stored in the ZFSVolume CR or on the node disk**, and is
fed to `zfs create` / `zfs load-key` over stdin. Note that the Secret-backed
modes (Mode 1 and Mode 3) keep the key in a Kubernetes Secret, typically in **etcd**
(base64, plaintext unless etcd encryption-at-rest is enabled); only the Vault
mode (Mode 2) keeps key material out of etcd entirely. See *Security notes*. The
dataset is created with `keylocation=prompt`, so the node reloads the key at
mount time (via `zfs load-key`), which lets encrypted volumes survive node
reboots.

Encrypted volumes carry `openebs.io/encrypted: "true"` in the PV's
`spec.csi.volumeAttributes` (a boolean marker — never the key), so you can tell a
PV is encrypted without inspecting the `ZFSVolume` CR:
`kubectl get pv <name> -o jsonpath='{.spec.csi.volumeAttributes.openebs\.io/encrypted}'`.
The authoritative source (and the key *source*: Secret vs KMS) remains the
`ZFSVolume` CR (`spec.encryption`, `spec.encryptionKeyRef`, `spec.encryptionKMSID`).

## Prerequisites

- A ZFS pool that supports encryption (OpenZFS >= 0.8).
- The external-provisioner runs with `--extra-create-metadata=true` (default in
  the shipped manifests) so the controller learns the PVC name/namespace.
- RBAC (already included in the Helm chart / operator YAML): the controller and
  node components can `get` Secrets and ConfigMaps cluster-wide; auto mode
  additionally lets the controller `create`/`update` Secrets, granted
  **namespaced** to the driver namespace only (deletion is handled by Kubernetes
  garbage collection, so no `delete` grant is needed).

---

## Mode 1 — Key from a Kubernetes Secret (per PVC)

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

Full example: [`deploy/sample/encrypted-pvc.yaml`](../deploy/sample/encrypted-pvc.yaml).

---

## Mode 2 — Key managed by HashiCorp Vault (KMS)

The driver generates a 32-byte key per volume and stores it in a Vault KV v2
engine at `<backend>/<keyPrefix>/<volume-id>`. It is fetched on the node to
create the dataset and to load the key at mount, and removed from Vault when the
volume is deleted.

Define the backend in a ConfigMap `openebs-zfs-kms-config` in the driver
namespace (keyed by a KMS id). The section is selected from the StorageClass
with `encryptionKMSID`.

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: openebs-zfs-kms-config
  namespace: openebs          # the driver namespace (OPENEBS_NAMESPACE)
data:
  vault-prod: |
    {
      "provider": "vault",
      "vaultAddress": "https://vault.example.com:8200",
      "vaultBackendPath": "secret",
      "vaultKeyPrefix": "zfs-localpv",
      "vaultAuthMethod": "token",
      "vaultTokenSecretName": "openebs-zfs-vault-token",
      "vaultSkipVerify": "false"
    }
---
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: openebs-zfspv-encrypted-vault
parameters:
  poolname: "zfspv-pool"
  fstype: "ext4"
  encryption: "aes-256-gcm"
  encryptionKMSID: "vault-prod"
provisioner: zfs.csi.openebs.io
```

For `token` auth, create the referenced token Secret in the driver namespace:

```bash
kubectl -n <driver-namespace> create secret generic openebs-zfs-vault-token \
  --from-literal=token="<vault-token>"
```

### Vault configuration keys

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `provider` | yes | — | Must be `vault`. |
| `vaultAddress` | yes | — | Vault API address (`https://host:port`). |
| `vaultBackendPath` | no | `secret` | KV v2 mount path. |
| `vaultKeyPrefix` | no | `zfs-localpv` | Path prefix under the mount. |
| `vaultNamespace` | no | — | Vault Enterprise namespace. |
| `vaultSkipVerify` | no | `false` | Skip TLS verification (not recommended). |
| `vaultCACert` | no | — | CA certificate PEM (inline) for TLS. |
| `vaultAuthMethod` | no | `token` | `token`, `kubernetes`, `cert`, or `mtls`. |
| `vaultToken` | no | — | Token value (discouraged — plaintext in the ConfigMap; prefer a Secret). |
| `vaultTokenSecretName` | no | — | Secret (driver namespace) holding the token under key `token`. |
| `vaultRole` | for `kubernetes` | — | Required for `kubernetes` auth; optional cert-role name for `cert`. |
| `vaultAuthPath` | no | `kubernetes`/`cert` | Vault auth mount path. |
| `vaultClientCertSecretName` | for `cert`/`mtls` | — | `kubernetes.io/tls` Secret (driver namespace) with `tls.crt`/`tls.key`. |
| `vaultClientCert` / `vaultClientKey` | alt. to the Secret | — | Inline client cert/key PEM. |

### Auth methods

- **token** — the token is read from `vaultToken` (inline, discouraged) if set,
  else the Secret named by `vaultTokenSecretName` (key `token`), else the
  `VAULT_TOKEN` env var.
- **kubernetes** — the pod's ServiceAccount JWT
  (`/var/run/secrets/kubernetes.io/serviceaccount/token`) is used to log in with
  `vaultRole`. No long-lived token to manage.
- **cert** — stock HashiCorp Vault TLS-certificate auth: the client certificate
  (from `vaultClientCertSecretName` or inline `vaultClientCert`/`vaultClientKey`)
  is presented over mTLS and exchanged at `auth/<vaultAuthPath|cert>/login` for a
  client token; `vaultRole` optionally selects a cert role.
- **mtls** — for KV v2 endpoints that authenticate **purely** at the TLS layer
  and have **no** login endpoint (e.g. OVHcloud OKMS): the client certificate is
  presented on every request and no bearer token is sent. Use this (not `cert`)
  for OKMS. Point `vaultAddress` at the OKMS REST endpoint including its
  `/api/<OKMS_ID>` prefix, and set `vaultCACert` to the OKMS REST CA.

> **OKMS read-after-write:** OVHcloud OKMS is eventually consistent — a key is
> not always readable for a few seconds after it is first written. At
> provisioning the driver waits (up to 30s) for the newly stored key to become
> readable before finishing `CreateVolume`, so the **first** provision of an
> OKMS-backed volume may take ~10s longer. Reads of an already-stored key (e.g.
> `zfs load-key` when a node reboots) are not affected, so recovery after an
> outage is not delayed. Strongly consistent backends (HashiCorp Vault, OpenBao)
> incur no such wait.

Full example: [`deploy/sample/encrypted-pvc-vault.yaml`](../deploy/sample/encrypted-pvc-vault.yaml).

---

## Mode 3 — Auto-generated key (no external KMS)

For zero-configuration per-volume encryption without running Vault, the driver
can generate the key itself and store it in a Secret it manages, in the OpenEBS
namespace. This is the recommended mode for operators and StatefulSets that
create PVCs on their own (via `volumeClaimTemplates`): each PVC gets its own
unique key with **nothing to configure per PVC**.

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
- The Secret is **deleted automatically** when the volume is deleted (only
  auto-managed Secrets are removed; user-provided ones are never touched).

**Security trade-off:** unlike the Vault mode, the key is stored at rest in a
Kubernetes Secret (typically in etcd, base64-encoded). Enable
[etcd encryption at rest](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/)
if this matters for your threat model, or use Mode 2 (Vault).

The managed Secret is the only copy of the generated key, so it is protected two
ways: **`immutable: true`** (blocks an accidental `kubectl edit`/patch that would
silently corrupt the key and make the volume unmountable) and an
**OwnerReference** to its ZFSVolume CR, which makes the Kubernetes garbage
collector reap the Secret automatically on every volume-deletion path (normal
teardown and out-of-band CR deletion alike) — no finalizer, and no explicit
delete. Do **not** manually `kubectl delete` the `zfs-enc-<volume>` Secret while
its PVC exists: it is the sole copy of the key, and removing it makes the volume
permanently unmountable. More generally, if a key stops matching its dataset
(an altered user Secret / KMS value, or a wrong key), `zfs load-key` is rejected
and the mount fails with a clear "encryption key … is incorrect … may have been
changed" error rather than silently mounting nothing.

Full example: [`deploy/sample/encrypted-pvc-auto.yaml`](../deploy/sample/encrypted-pvc-auto.yaml).

### Choosing a mode

| Mode | Per-PVC config | Key at rest | Best for |
|------|----------------|-------------|----------|
| 1. Secret (bring your own) | annotation + Secret | your Secret | full control over the key |
| 2. Vault KMS | none (SC only) | Vault | production, operators/STS, strong key custody |
| 3. Auto Secret | none (SC only) | k8s Secret (etcd) | operators/STS without KMS infra |

### Combining modes (hybrid)

The modes are evaluated in precedence order, so a **single StorageClass can serve
both "bring your own key" and "auto" users**:

1. PVC annotation `local.zfs.openebs.io/encryption-secret` (Mode 1), else
2. `encryptionKMSID` on the StorageClass (Mode 2), else
3. `autoCreateEncryptionKey: "true"` on the StorageClass (Mode 3).

So a StorageClass with `autoCreateEncryptionKey: "true"` auto-generates a key
**only when the PVC does not provide one** via the annotation. A developer who
sets the annotation overrides the auto behaviour for their PVC.

If the annotation references a Secret that is missing or does not contain a valid
64-char hex key, provisioning fails immediately with a clear `InvalidArgument`
error (it does **not** silently fall back to auto-generation).

---

## Snapshots, clones, backup/restore

- **Clones** (from a volume or a snapshot) inherit the parent's encryption root
  and its key source. The node ensures the parent key is loaded before
  `zfs clone`, and the clone loads the (shared) key at mount.
- **Backup/restore** (Velero via `zfs send | nc` / `nc | zfs recv`): an
  encrypted restore fetches the key and hands it to `zfs recv` through a
  transient `0600` key file (recv's stdin carries the data stream, so `prompt`
  cannot be used during receive). After the receive, the dataset is switched
  back to `keylocation=prompt` and the temp file removed.

---

## Key rotation (manual)

Automated rotation is intentionally **not** performed by the driver: there is no
standard CSI trigger for it, and an interrupted rotation can make data
unrecoverable. Rotate manually per volume on the owning node:

```bash
# 1. Generate the new key and ensure the current key is loaded.
NEWKEY=$(openssl rand -hex 32)
zfs load-key <pool>/<pv-name>        # feed the current key on stdin

# 2a. Vault mode: write the new key to Vault first, then re-wrap.
vault kv put secret/zfs-localpv/<pv-name> key="$NEWKEY"
printf '%s' "$NEWKEY" | zfs change-key -o keyformat=hex -o keylocation=prompt <pool>/<pv-name>

# 2b. Secret mode: update the Secret first, then re-wrap with the new value.
kubectl -n <ns> patch secret <name> -p '{"stringData":{"key":"'"$NEWKEY"'"}}'
printf '%s' "$NEWKEY" | zfs change-key -o keyformat=hex -o keylocation=prompt <pool>/<pv-name>
```

`zfs change-key` re-wraps the dataset master key; existing data is not
re-encrypted. Store the new key in the backend **before** running
`change-key` so a crash between the two steps leaves a recoverable state.

---

## Security notes

- Key material is never written to the ZFSVolume CR or the node disk, and is fed
  to `zfs` over stdin (for restore, via a transient `0600` temp file that is
  removed after the receive). **Secret-backed modes (1 and 3) store the key in a
  Kubernetes Secret, typically in etcd** (base64) — enable
  [etcd encryption at rest](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/),
  or use Vault (Mode 2), when key custody matters.
- gRPC request/response logging strips secrets, and the key is passed to `zfs`
  on stdin, so it never appears in process arguments or logs.
- The controller and node are granted cluster-wide `get` (not `list`) on Secrets
  because a referenced Secret can live in any PVC namespace. Auto-mode
  `create`/`update` on Secrets is granted **namespaced** to the driver namespace
  only (`openebs-zfs-provisioner-secrets-role`), not cluster-wide; no `delete`
  grant is needed since the Secret is garbage-collected via its OwnerReference.

## Upgrades and compatibility

Per-volume encryption adds only **optional** fields to the existing `ZFSVolume`,
`ZFSSnapshot` and `ZFSRestore` CRD schemas (`encryptionKeyRef`,
`encryptionKMSID`) — no new CRD API version and no conversion webhook. Upgrading
from a release without this feature is therefore backward-compatible:

- The chart ships CRDs as templates (not via Helm's install-only `crds/`
  directory), so `helm upgrade` **applies the schema change**: the new optional
  fields are added to the CRDs and the driver images roll. Existing volumes —
  encrypted or not — keep working, and their CRs stay valid (the new fields are
  simply absent on pre-upgrade volumes). Legacy `keylocation`-file encryption is
  unaffected.
- Use a **single install method** — the Helm chart *or* the operator YAML, not
  both. `helm upgrade` only succeeds when Helm owns the resources (same release
  name/namespace, `meta.helm.sh/release-*` metadata); upgrading a release whose
  CRDs/RBAC were applied by the other method fails with an ownership error.

> **⚠️ Downgrade warning.** Do **not** downgrade to a version whose CRD schema
> lacks these fields while encrypted volumes exist. Kubernetes structural-schema
> pruning would silently strip `encryptionKeyRef` / `encryptionKMSID` from
> existing `ZFSVolume` CRs on their next write, so the driver could no longer find
> the key and those volumes would become unmountable. Downgrades across this
> feature are unsupported.

## Limitations

- The managed per-volume key is always `hex` (a 32-byte key as 64 hex chars).
  The legacy StorageClass `keyformat` (`passphrase`/`raw`/`hex`) is unaffected.
- Vault backend: KV v2 only; `token`, `kubernetes`, `cert` (stock Vault TLS-cert
  login) and `mtls` (TLS-only, e.g. OKMS) auth.
- Key rotation is manual (see above) — the driver performs no automatic rotation
  for either the per-volume or the legacy StorageClass encryption.
- **Backup/restore under a new volume name**: the per-volume key is looked up by
  the volume's own name/Secret reference. Restoring an encrypted volume under a
  *different* name (e.g. some Velero flows) will not find the original key —
  restore preserving the volume name, or pre-provision the key under the new name.

The legacy `keylocation`-file StorageClass encryption continues to work unchanged
alongside per-volume keys.
