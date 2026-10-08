# Security dependency migration

PyO3 uses 0.29.3. HQC is removed from the dependency graph; Kyber-768 and
Dilithium3 use their direct crates instead of the incompatible pqcrypto 0.15
umbrella. Algorithm names are retained; this change does not migrate to ML-KEM
or ML-DSA.

The native build was blocked by an unfinished laser refactor. The missing type
definitions are restored from commit `179b747f0dc5a58984ea7b2a61072bedc60b6ce7`,
while the existing laser method implementations are retained. Python synchronous
calls now await the core methods on a persistent Tokio runtime with the GIL
released. Permission checks no longer reacquire an already-held mutex.

## Python compatibility changes

Previously uncompilable wrappers now use the actual Rust interfaces:

| Interface | Supported values or behavior |
| --- | --- |
| `PySecurityManager(level)` | `Minimum`, `SensitiveEscalation`, `Locked` |
| `check_permission(permission, scope)` | Permission: `Discussion`, `AccessAuth`, `Command`, `Pairing`, `FileTransfer`; scope: `Single`, `Group`, `All`, `Session` |
| `PyChannelData(channel_type, data, timestamp, sequence_id)` | Fourth argument is a sequence ID; quality is computed by the validator. Timestamp is finite, nonnegative UNIX seconds, and must not be in the future. |
| Alignment getters | `beam_position_x`, `beam_position_y` in pixels; degree getters are removed because the core does not measure degrees. |
| Performance getters | Throughput is converted from bps to Mbps; latency is the measured handshake latency. The unsupported CPU usage getter is removed. |
| `measure_distance_averaged(samples)` | Uses the requested sample count; accepts 1–1000. |

Unknown policy, permission and scope values raise errors. Denied operations and
invalid PINs remain rejected. Range detectors can be shared with a laser engine
without transferring or replacing their state.

## Post-quantum behavior

KEM encapsulation returns both the ciphertext and sender's shared secret;
decapsulation must use the recipient's corresponding secret key. Signatures use
Dilithium3 detached signatures, and parsing uses the crate's real length checks.

The old `hybrid_key_exchange` API cannot return a ciphertext to the peer and
attempted to decapsulate a peer ciphertext with the sender's secret key. It now
returns an explicit error. Applications needing hybrid exchange must implement
a reviewed two-party ciphertext exchange before enabling that operation.

Long-lived serialized PQ secret keys and stored shared secrets are held in
`Zeroizing` buffers. The upstream crates create internal key copies that this
change cannot guarantee are wiped. This is not a complete memory-erasure audit.

## Validation

```sh
cargo check --locked --features python,post-quantum
cargo test --locked --lib
cargo test --locked --lib --test security_algorithms --features post-quantum
cargo build --locked --lib --features python,post-quantum
REALGIBBER_CORE_LIBRARY="$PWD/target/debug/libgibberlink_core.so" \
  timeout 30s python ../tests/test_native_security_migration.py -v
```

These checks cover the Linux native module, Rust core, retained PQ algorithms,
access denial, PIN rejection, invalid timestamps, tampering and state sharing.
They do not establish Android hardware, WASM or production deployment readiness.
