# SplitKey camera appliance: motion (detection) + sealerd (sealing) in one image.
# The sealer binaries are static-pie x86_64 — the base only supplies the motion
# daemon and its libav* deps. No ffmpeg CLI: motion encodes via libavcodec.
FROM debian:stable-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends motion ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY bin/sealerd bin/sealer bin/sks /usr/local/bin/
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/sealerd /usr/local/bin/sealer \
             /usr/local/bin/sks /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
