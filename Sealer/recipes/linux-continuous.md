# Recipe: continuous sealed camera (Linux + USB cam, pipe mode)

24/7 recording with plaintext only in RAM — the same pipeline shape a
camera SoC will use (hardware encoder → pipe → seal).

```
USB cam → ffmpeg (V4L2, H.264) → stdout → sealerd pipe mode → S3
```

## sealerd config

Mode A in `sealer.example.toml` is exactly this:

```toml
[source]
mode = "pipe"
[source.pipe]
format  = "mpegts"
command = "ffmpeg -hide_banner -loglevel error -f v4l2 -framerate 30 -video_size 1280x720 -i /dev/video0 -c:v libx264 -preset veryfast -tune zerolatency -g 30 -f mpegts -"

[sealing]
segment_max_secs  = 60
segment_max_bytes = "16MB"
```

sealerd spawns and supervises the recorder: if ffmpeg dies it restarts with
backoff, and the outage is *declared* on the evidence record as
`source_lost` / `source_restored` chain events.

## Notes

- Check your camera's real modes first: `v4l2-ctl --list-formats-ext`
  (package `v4l-utils`). Pick a mode the camera natively supports.
- Many UVC cameras output MJPEG at higher resolutions — let ffmpeg
  transcode (`-input_format mjpeg` before `-i`), or on SoCs use the
  hardware encoder (`h264_v4l2m2m` on Pi, `h264_rkmpp` on Rockchip).
- Encoder choice trades CPU for privacy-surface: everything stays in this
  one pipeline either way.
- Storage math at defaults: 1280x720 x264 veryfast ≈ 2–4 Mbps ≈
  1.3–2.6 GB/hour/camera. Size buckets and retention accordingly.
- systemd: see the device-access lines commented in `sealerd.service`
  (`SupplementaryGroups=video`, `DeviceAllow=/dev/video0`).

## macOS equivalent

`Sealer/demo-usbcam.sh` is this same recipe with `avfoundation` instead of
V4L2 — useful for development without touching the deployment box.
