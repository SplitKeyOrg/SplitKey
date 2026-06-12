# Installing the SplitKey Sealer on a Linux box

Static binaries — no dependencies, any x86_64 Linux (glibc or musl).

```sh
# 1. Binaries
sudo install -m755 sks sealer sealerd /usr/local/bin/

# 2. User + dirs
sudo useradd --system --home /var/lib/splitkey splitkey || true
sudo mkdir -p /etc/splitkey /var/lib/splitkey
sudo chown splitkey:splitkey /var/lib/splitkey

# 3. Ceremony artifacts (from your community's key ceremony — or for a
#    trial run, generate a simulated one):
sks ceremony-sim --community my-community --windows 540 --out /tmp/ceremony
sudo cp /tmp/ceremony/manifest.skm /tmp/ceremony/admin.pub /etc/splitkey/
#    (ceremony-sim also writes crk.secret — that file is the master key
#     simulation; keep it OFF this machine in any real deployment)

# 4. Config — start from the example, set camera_id + storage:
sudo cp sealer.example.toml /etc/splitkey/sealer.toml
sudoedit /etc/splitkey/sealer.toml

# 5. Enroll (generates the device key, pins the admin key):
sudo -u splitkey sealer --config /etc/splitkey/sealer.toml enroll

# 6. Health check, then service:
sudo -u splitkey sealer --config /etc/splitkey/sealer.toml doctor
sudo cp sealerd.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now sealerd
sleep 15 && sudo -u splitkey sealer --config /etc/splitkey/sealer.toml status
```

For pipe mode with a USB camera: `sudo usermod -aG video splitkey`, install
ffmpeg, and see the commented device lines in `sealerd.service`.

For motion-triggered recording: see `recipes/linux-motion.md` in the repo.
