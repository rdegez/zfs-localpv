# Design — per-PersistentVolume ZFS encryption (Kubernetes Secret / KMS)

Status: implemented · Area: node + controller · Additive, opt-in.

## Summary

Today zfs-localpv can only encrypt volumes with a single static key shared by a
whole StorageClass (a `keylocation` file present on every node). This design adds
**per-PersistentVolume** ZFS native encryption: each PV is encrypted with its own
32-byte key, sourced from one of three backends, and reloaded at mount so
encrypted volumes survive node reboots. It is fully additive — with none of the
new parameters/annotations set, behaviour is byte-for-byte unchanged and the
legacy `keylocation`-file mode keeps working.

## Goals

- A distinct key per PV, from any of: a user-provided Kubernetes Secret, a KMS
  backend (HashiCorp Vault KV v2), or a driver-generated & driver-managed Secret.
- Key material never persisted to the ZFSVolume CR or to node disk.
- Encrypted volumes survive node reboots (the driver reloads the key at mount).
- Works across the existing snapshot / clone / backup-restore paths.
- No new Go module dependency (`go.mod`/`go.sum` unchanged; Vault client uses the
  standard library `net/http`).
- Fail **closed**: never silently create a plaintext volume when encryption was
  requested.

## Non-goals

- **Automated key rotation.** There is no standard CSI trigger, and an
  interrupted `zfs change-key` can make data unrecoverable without a two-phase
  protocol. A manual runbook is documented instead (`docs/encryption.md`).
- **Re-encrypting existing data.** `zfs change-key` re-wraps the master key only.
- **Changing the key source of an existing volume.** The controller sets the
  reference once at create and never mutates it; it is not enforced immutable by
  the CRD (see *Known limitations*).

## Architectural context (ZFS facts this relies on)

- A key is loaded onto an *encryption root*; child datasets inherit it. Clones
  share the parent's encryption root and therefore its key.
- With `keyformat=hex`, the key is a 32-byte value written as 64 hex chars.
- With `keylocation=prompt`, `zfs create` / `zfs load-key` read the key from
  **stdin** — this is how we feed the key without it ever reaching argv, a file,
  or the CR.
- A dataset created `keylocation=prompt` does **not** auto-load its key on pool
  import (reboot); it must be re-loaded explicitly. Hence load-key at mount.
- For a zvol, the `/dev/zvol/<pool>/<name>` device node is (re)created by udev
  **asynchronously** after the key becomes available — consumers must wait for it.
- `zfs recv` takes the send stream on stdin, so the key cannot be piped during a
  receive; a transient key file is required for encrypted restore.
- `zfs destroy` does **not** require the key to be loaded.

## Key sources & precedence

Three opt-in signals; the controller resolves them in a fixed precedence order
so a single StorageClass can serve any mode:

1. **Per-PVC Secret** — the PVC carries `local.zfs.openebs.io/encryption-secret:
   <name>`; the key comes from that Secret (in the PVC namespace), data key `key`.
2. **KMS (`encryptionKMSID`)** — a StorageClass parameter selecting a backend
   section of the `openebs-zfs-kms-config` ConfigMap (Vault).
3. **Auto (`autoCreateEncryptionKey: "true"`)** — the driver generates a key and
   stores it in a Secret it manages.

**Fail-closed rule:** if any of these signals is present but the StorageClass
does not also set the `encryption` parameter, `CreateVolume` is rejected with
`InvalidArgument` rather than provisioning an unencrypted volume.

## Components

### `pkg/kms` — key-store abstraction

A slim interface (deliberately smaller than ceph-csi's, since ZFS does its own
key wrapping — we only need a per-volume key store, not DEK wrapping):

```
type KeyStore interface {
    GetOrCreateKey(ctx, volumeID) (hexKey, error) // controller create
    FetchKey(ctx, volumeID) (hexKey, error)        // node create + mount
    RemoveKey(ctx, volumeID) error                 // controller delete (no-op for user Secrets)
    Destroy()
}
```

Providers register in an init-time registry keyed by name:
- `k8s-secret` (`k8ssecret.go`) — reads a user Secret; `RemoveKey` is a no-op
  (the user owns it). Also home to `GenerateHexKey` / `ValidateHexKey`.
- `vault` (`vault.go`) — HashiCorp Vault KV v2 over `net/http`.
- Config for `vault` is loaded from the KMS ConfigMap (`config.go`).

### API / CRD

Three scalar string fields on `VolumeInfo` (v1 and v1alpha1), so no deepcopy
regeneration is needed. Only a *reference* is stored — never key material:
- `encryptionKeySecretName`, `encryptionKeySecretNamespace` (Secret & auto modes),
- `encryptionKMSID` (Vault mode).

### Controller — `CreateZFSVolume`

1. Read the three signals (annotation via `GetPVC`, `encryptionKMSID`,
   `autoCreateEncryptionKey` parsed with `strconv.ParseBool`).
2. Apply the fail-closed rule.
3. Resolve by precedence:
   - Secret: validate it (exists + valid hex) up front → fail fast on the
     controller with a clear message instead of on the node.
   - KMS: generate+store the key in Vault now, so it exists before the node
     creates the dataset.
   - Auto: generate the key and store it in `zfs-enc-<volume-id>` (driver
     namespace), labelled `local.zfs.openebs.io/auto-managed=true`; idempotent.
4. Force `keyformat=hex`, record the reference on the CR, and do **not** persist a
   legacy `keylocation` in managed mode.
5. Set `openebs.io/encrypted: "true"` in the CreateVolume response volume context
   (read back from the CR, so it covers all modes and clones/restores). The
   external-provisioner copies it into the PV's `spec.csi.volumeAttributes`,
   making encryption visible on the PV — a boolean marker only, never the key.

A transient `GetPVC` failure is only fatal when the annotation is the *sole*
possible source (no KMS/auto), so it never blocks KMS/auto encrypted volumes.

### Controller — deletion

Key/Secret cleanup is centralised in `zfs.DeleteVolume` via
`CleanupEncryptionKey`, and runs **after** the CR is successfully deleted. This:
- covers every destroy path (immediate delete, delete-after-last-snapshot, and
  create rollback), so keys are not orphaned for volumes that had snapshots;
- never removes the key of a volume whose CR delete failed (it would become
  unmountable);
- does not gate CR deletion on a slow/unreachable KMS.
Removal is best-effort (logged on failure). `zfs destroy` on the node needs no key.

### Node — create & mount

- **Create**: build args with `keylocation=prompt`; fetch the key and pipe it to
  `zfs create` on stdin.
- **Mount** (`EnsureKeyLoaded`): if the dataset's key is `unavailable`, load it on
  the encryption root from stdin. "Key already loaded" (a concurrent
  clone/mount) is treated as success. For a zvol, then wait for
  `/dev/zvol/<pool>/<name>` to appear (bounded, `ctx`-aware; timeout overridable
  via `ZFS_ZVOL_DEVICE_WAIT_TIMEOUT`) to avoid an ENOENT mount race after reboot.
- **Clone**: load the parent's key before `zfs clone` (clones inherit the key).
- **Restore**: write the key to a transient `0600` file, `keylocation` at it for
  the receive, then reset the dataset to `keylocation=prompt` (hard error if that
  reset fails — otherwise the volume would be unmountable) and remove the file.

### Vault provider

KV v2 REST at `<addr>/v1/<backend>/{data,metadata}/<prefix>/<volume-id>`. Auth:
- `token` — inline (discouraged; warned) → Secret (`vaultTokenSecretName`) → `VAULT_TOKEN`.
- `kubernetes` — ServiceAccount JWT → `auth/<path>/login`.
- `cert` — stock Vault TLS-cert auth: present a client cert and exchange it at
  `auth/<path>/login` for a token.
- `mtls` — for endpoints that authenticate purely at the TLS layer with no login
  endpoint (e.g. **OVHcloud OKMS**): present the client cert, send no token.
Optional custom CA (`vaultCACert`), `vaultNamespace`, and `vaultSkipVerify`
(warned — disables verification of the KMS holding every key).

## Security model

- Key material is fed to `zfs` on **stdin** — never in process args, the CR, or
  node disk. The key never enters the CSI gRPC API either (it is read
  server-side from the Secret/KMS, not passed in requests).
- **etcd caveat:** the Secret-backed modes (per-PVC and auto) keep the key in a
  Kubernetes Secret, i.e. in etcd (base64). Recommend etcd encryption at rest, or
  the Vault mode, when key custody matters. Only Vault keeps keys out of etcd.
- **RBAC (least privilege):** `get`/`list` Secrets cluster-wide is required
  because a user Secret can live in any PVC namespace; the auto-mode
  `create`/`update`/`delete` on Secrets is granted **namespaced** to the driver
  namespace only (`openebs-zfs-provisioner-secrets-role`), not cluster-wide.
- **Concurrency:** the kube client is built lazily and cached only on success
  (retried on transient error). Concurrent `load-key` on a shared encryption root
  is safe ("already loaded" ⇒ success).
- **Auto Secret adoption:** `provisionAutoKeySecret` refuses to reuse a
  pre-existing Secret that is not labelled auto-managed, so a user-created Secret
  is never silently adopted as a volume key.
- **Key integrity & cleanup:** the driver-managed auto Secret is the sole copy of
  a generated key, so it is protected two ways: `immutable: true` (blocks a
  corrupting edit/patch that would make the volume unmountable) and an
  OwnerReference to its ZFSVolume CR. The OwnerReference is the *sole* cleanup
  mechanism: Kubernetes garbage-collects the Secret automatically whenever the CR
  is deleted, which covers every teardown path — normal DeleteVolume and
  out-of-band CR deletion the controller never sees alike — with no finalizer, no
  node-side deletion code, and no `delete` RBAC grant. This deliberately does not
  block an operator manually deleting the Secret while the volume lives (a
  finalizer would, but at the cost of stuck-`Terminating` failure windows on every
  teardown, retry-on-conflict clearing code, and a node `delete` grant — judged
  disproportionate); the "do not delete the key Secret" contract is documented
  instead. The OwnerReference is attached best-effort just after the CR is created
  and re-asserted on idempotent CreateVolume retries. A key that no longer
  matches its dataset (malformed ⇒ caught by hex validation at create and at
  every load-key; valid-but-wrong ⇒ `zfs load-key` rejects it) fails the mount
  with an explicit "incorrect key … may have been changed" error, never mounting
  an unusable volume.

## Testing

- Unit: create-arg builders (prompt vs legacy file), `k8s-secret` provider,
  hex validation, precedence/`UsesManagedKey`; auto-Secret provision/idempotency/
  immutability/adoption-refusal (fake clientset); `waitForDevice` (appear/timeout/ctx
  cancel) + configurable timeout; encrypted restore-arg building; Vault provider
  against an httptest KV v2 server incl. `cert`-login token propagation and an
  `mtls` server that requires+verifies the client certificate.
- e2e (manual, on a real ZFS pool): auto mode across replicas, node-reboot
  recovery, auto-Secret deletion on PVC delete. Live Vault/OKMS e2e is pending.

## Rollout / phasing

Shipped as four incremental, stacked PRs, each building/testing green on its own:
`01 secret-key` → `02 auto-key` → `03 clone-restore` → `04 vault-kms`. Each field
appears only with the PR that uses it (e.g. `encryptionKMSID` lands in PR 4).

Generated manifests (CRDs, `deploy/zfs-operator.yaml`, Helm CRD templates) are
kept consistent by hand to avoid unrelated churn from helm-version quoting
differences; the Go API types and the CRD YAML are kept in sync.

## Known limitations / open questions

- **Restore under a new volume name** won't find the original key (keyed by
  volume name / Secret reference). Restore preserving the name, or pre-provision
  the key.
- **Auto-Secret orphan window:** the OwnerReference is attached only *after* the
  CR exists (its UID is unknown at Secret-create time), so a controller crash
  between Secret creation and `SetAutoKeySecretOwner` — and never followed by a
  CreateVolume retry that re-asserts it — leaves an ownerless Secret that GC won't
  reap. It is a plain, deletable leftover (no finalizer, not stuck), not a
  mount-blocking condition. Narrow; a periodic sweep of `auto-managed=true`
  Secrets with no matching ZFSVolume would close it.
- **Delete-time key removal is best-effort** — if the KMS is unavailable, the key
  is orphaned there (surfaced only as a warning).
- **Mount latency after reboot:** `NodePublishVolume` for an encrypted zvol waits
  for the device node to appear, up to the (bounded, `ctx`-cancellable) device
  timeout per volume — normally milliseconds, but a stalled udev would delay that
  volume's publish.
- **Mutual-exclusivity / immutability** of the API fields lives in controller
  precedence, not in CRD validation (consistent with the project's marker-free
  hand-written CRDs).
