# SplitKey camera appliance (containerized)

Motion-triggered, self-sealing camera in a single container:

```
USB cam (/dev/video0) → motion (detection) → /dev/shm (RAM) → sealerd → ./archive
```

Plaintext footage exists only in the container's tmpfs (`/dev/shm`). Sealed
`.sks` segments land in `./archive` on the host — a bind mount, not a docker
volume — and the hash-chain heartbeat proves aliveness during quiet hours.

## Layout

| path            | what                                                      |
|-----------------|-----------------------------------------------------------|
| `bin/`          | static sealer binaries — fetched, not committed (see below) |
| `config/`       | `sealer.toml`, `motion.conf`; ceremony artifacts + `state/` (device key + chain head) after init |
| `archive/`      | **sealed output** (`.sks` / `.skc`)                       |

## Run

```sh
# 0. get the binaries into ./bin/ (they aren't committed — see fetch-binaries.sh).
#    If they haven't been built yet, build first:  ( cd ../../Sealer && ./dist/build-linux.sh )
./fetch-binaries.sh

# 1. one-time provisioning (simulated ceremony + enrollment)
docker compose run --rm init

# 2. start the appliance
docker compose up -d --build

# 3. watch it
docker compose logs -f sealer

# verify the sealed chain at any time
docker compose run --rm --entrypoint sks sealer verify /archive --device-pub /config/state/device.pub
```

## Notes

- **Camera:** `/dev/video0` is passed through and containers run as **root** so
  the device (root:root in-container) is reliably readable. Sealed files are
  therefore root-owned on the host, but world-readable.
- **tmpfs:** clips queue in `/dev/shm` only between file-close and seal (~2 s);
  `shm_size` is 256m, far more than the < 100 MB a busy 1080p cam needs.
- **Trial ceremony:** `init` runs `sks ceremony-sim`, which writes
  `config/ceremony/crk.secret` — the master-key stand-in. Fine for this soak;
  in a real deployment that file never lives on the camera box.
- **Detection tuning:** `motion.conf` `threshold`, masks, framerate, etc. are
  orthogonal to sealing — adjust freely.
