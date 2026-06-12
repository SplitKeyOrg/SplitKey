# Sealer simulation environment

A synthetic SplitKey community in Docker (docs/09): a fake camera records
clips, `sealerd` seals them, MinIO stores them under object lock, a fs
archive mirrors them, and a verifier container continuously chain-audits
everything **without any decryption keys**.

```
docker compose up --build
```

Watch it run:

- `docker compose logs -f sealerd` — sealing + uploads
- `docker compose logs -f verifier` — keyless chain verification every 15 s
- MinIO console: http://localhost:19001 (minioadmin / minioadmin)

## Simulated release

The ceremony container leaves `crk.secret` in the `community` volume
(simulation only — a real ceremony prints shares and destroys the CRK):

```sh
# pick a sealed segment and find its window
docker compose exec sealerd sks inspect /archive/sim-community/sim-cam-1/1/<window>/<seq>.sks

# derive that window's key and unseal
docker compose exec sealerd sks release --crk /community/crk.secret --window <window> --out /tmp/wk.key
docker compose exec sealerd sks unseal /archive/.../<seq>.sks --window-key /tmp/wk.key --out /tmp/clip.mp4
```

## Chaos drills

The verifier should stay green through all of these *except* the ones that
are actual evidence destruction — which it must catch:

| Drill | Expected outcome |
|-------|------------------|
| `docker compose kill -s KILL sealerd` then `up sealerd` | Chain resumes; new `boot` chain event; verifier stays green; stale tmp cleaned |
| `docker compose pause minio` for a while, then unpause | Spool grows, then drains; fs archive keeps verifying throughout |
| Stop the camera (`docker compose stop camera`) | Heartbeat chain events appear every 60 s — silence is declared, not suspicious |
| Delete a middle `.sks` from the **fs archive** volume | Verifier exits red: `sequence gap` |
| Flip a byte in an archived `.sks` | Verifier exits red: `body hash mismatch` |
| Try `mc rm` on an object in `sealed/` | Plain `rm` only adds a *delete marker* (versioning); the sealed version survives. `mc rm --version-id …` — actual destruction — is denied: "WORM protected", even for the storage root admin |

## Operator commands inside the container

```sh
docker compose exec sealerd sealer --config /etc/splitkey/sealer.toml status
docker compose exec sealerd sealer --config /etc/splitkey/sealer.toml doctor
```
