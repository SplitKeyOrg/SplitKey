# 07 — Configuration & CLI

Philosophy: **one TOML file deploys a camera.** CLI flags exist for
overrides and one-shot tools; everything operational lives in the file so
fleet deployment is "drop file, start service."

## File locations & precedence

1. `--config <path>` flag
2. `$SEALER_CONFIG`
3. `/etc/splitkey/sealer.toml` (Linux), `%ProgramData%\SplitKey\sealer.toml` (Windows)

Precedence: CLI flag > env var (`SEALER_*` for selected keys) > file >
built-in default. `sealer doctor` prints the fully-resolved effective config
(redacted).

## Example `sealer.toml` (the documentation artifact — every key shown)

```toml
[community]
id            = "maplecourt-hoa"            # must match pubkey manifest
manifest      = "/etc/splitkey/manifest.skm"
admin_pubkey  = "/etc/splitkey/admin.pub"   # pinned at enrollment

[device]
camera_id     = "lobby-east"
state_dir     = "/var/lib/splitkey/sealer"  # signing key, chain state, spool
signing_key   = "state"                     # "state" | "tpm" | "file:<path>"

[source]
mode = "watch"                              # watch | pipe | rtsp

  [source.watch]
  path          = "/var/spool/camera/clips"
  ready_glob    = "*.mp4"                   # files matching are candidates
  ignore_glob   = "*.tmp"
  stable_secs   = 2                         # size-stable fallback detector
  after_seal    = "delete"                  # delete | keep

  # [source.pipe]
  # format      = "h264-es"                 # h264-es | h265-es | mpegts
  # [source.rtsp]
  # url         = "rtsp://10.0.0.12:554/stream1"
  # transport   = "tcp"
  # credential  = "env:SEALER_RTSP_CRED"

[sealing]
suite           = "SKS1-XCHACHA"            # SKS1-XCHACHA | SKS1-AESGCM
segment_max_secs  = 60
segment_max_bytes = "16MB"
chunk_bytes       = "64KB"
manifest_exhausted = "seal-to-last-key"     # | "fail-closed"

[chain]
heartbeat_secs  = 300
anchor          = []                        # e.g. ["tsa:https://tsa.example", "log:https://log.example"]
clock_skew      = "warn"                    # warn | hold-uploads | stop

[spool]
quota         = "4GB"
when_full     = "drop-oldest-uploaded"      # then: drop-oldest | stop-recording

[[storage]]                                 # repeatable: multi-sink fan-out
type          = "s3"
endpoint      = "https://s3.us-west-000.backblazeb2.com"
bucket        = "maplecourt-footage"
prefix        = "sealed/"
credential    = "file:/etc/splitkey/s3.secret"
object_lock   = { mode = "compliance", days = 90 }

# [[storage]]
# type        = "fs"
# path        = "/mnt/nas/sealed"

[catalog]
mode          = "objects"                   # default: signed .skc records + per-window
                                            #   index written to the storage sinks;
                                            #   no catalog server exists or is needed
# url         = "https://..."               # optional future: additionally POST records
                                            #   to an HTTP endpoint (device-key signed)

[control]
health_listen = "127.0.0.1:9465"            # GET /healthz, /metrics (Prometheus)
qr_actions    = true                        # see 08-qr-actions.md
qr_source     = "inline"                    # inline (scan own video) | none

[log]
level         = "info"
format        = "json"                      # json | text
```

## CLI surface

```
sealerd [--config PATH] [--check]        # the daemon; --check = validate config and exit

sealer enroll --manifest m.skm --admin-key admin.pub [--camera-id X]
                                          # first-time setup: pin keys, create state,
                                          #   generate + register device signing key
sealer doctor                             # config resolution, backend reachability,
                                          #   bucket lock verification, entropy, clock
sealer status                             # pipeline state, spool depth, chain head, last upload
sealer reload                             # SIGHUP equivalent (re-read config/credentials)
sealer rotate-manifest new.skm            # verify (signed by pinned admin chain) and install

sks verify <path|url-prefix> [--json]     # chain/signature verification, NO keys needed
sks inspect <file.sks>                    # dump header/footer
```

Conventions: exit codes stable and documented (scripting), `--json`
everywhere for machine use, no interactive prompts in `sealerd` (it must run
as a service: systemd unit + Windows service wrapper ship in `dist/`).

## Validation behavior

- Unknown keys: **error** (typos must not silently no-op a security setting).
- Missing manifest/admin key: refuse to start.
- `manifest_exhausted`, `when_full`, `clock_skew` all have safety-relevant
  defaults documented inline above; `sealer doctor` warns when a deployment
  combination weakens guarantees (e.g. object_lock absent, single storage
  sink, no anchoring).

## Fleet deployment notes

- Config is fully declarative → image-bake or ansible/scp-able.
- Per-device deltas are exactly two keys (`camera_id`, credentials), so a
  fleet template + small per-device overlay file
  (`sealer.toml` + `sealer.local.toml`, shallow-merged) is supported.
- A `config_change` chain event (redacted hash) records every effective
  config change on the evidence record itself.
