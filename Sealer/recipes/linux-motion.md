# Recipe: motion-triggered sealed camera (Linux + USB cam)

The composition the Sealer is designed for: detection stays in a dedicated,
maintained tool (the [`motion` daemon](https://motion-project.github.io/) —
note: *MotionEyeOS* the distro is dead, the `motion` daemon is alive and in
every distro repo), and the file handoff happens through **tmpfs**, so
plaintext clips live in RAM only and never touch flash.

```
USB cam → motion (detection) → /dev/shm/splitkey-clips (RAM) → sealerd → S3
```

## 1. tmpfs clip directory

`/dev/shm` is already a tmpfs on every modern Linux:

```sh
sudo mkdir -p /dev/shm/splitkey-clips        # recreate on boot (see below)
sudo chown motion:splitkey /dev/shm/splitkey-clips
sudo chmod 770 /dev/shm/splitkey-clips
```

For boot persistence add to `/etc/tmpfiles.d/splitkey.conf`:

```
d /dev/shm/splitkey-clips 0770 motion splitkey -
```

Size note: clips queue here only between file-close and seal (~2 s). Even a
busy 1080p camera needs < 100 MB of headroom.

## 2. motion config (`/etc/motion/motion.conf` essentials)

```
video_device /dev/video0
width 1280
height 720
framerate 15

# write event movies straight to the tmpfs handoff dir
target_dir /dev/shm/splitkey-clips
movie_output on
movie_codec mkv
movie_max_time 60          # ≈ one Sealer segment per minute of motion

# privacy posture: no stills, no live stream port, no webcontrol
picture_output off
stream_port 0
webcontrol_port 0
```

## 3. sealerd config (`/etc/splitkey/sealer.toml`)

Use Mode B from `sealer.example.toml`:

```toml
[source]
mode = "watch"
[source.watch]
path        = "/dev/shm/splitkey-clips"
ready_glob  = "*.mkv"
stable_secs = 2
after_seal  = "delete"
```

## 4. What you get

- Motion-triggered recording (no 24/7 storage burn)
- Plaintext only ever in RAM; sealed `.sks` on disk within seconds
- Sealer heartbeat chain events cover the quiet hours, so "no motion all
  night" is provable aliveness, not a suspicious gap
- motion's detection settings (`threshold`, masks, etc.) are orthogonal to
  sealing — tune freely

## Caveats (stated honestly)

- Power loss loses any clip not yet sealed (≤ ~2 s window). Acceptable
  trade for keeping plaintext off flash.
- motion sees plaintext by definition — it runs inside the camera trust
  boundary. Keep the box itself hardened; that's true of any detector.
- `movie_max_time` clips spanning a window boundary seal to the window of
  their first byte (decided: docs/11, Q11).
