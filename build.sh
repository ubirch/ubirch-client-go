#!/bin/bash
make arm
docker build -t ubirch/ubirch-go-udp-client:arm64 .
docker push ubirch/ubirch-go-udp-client:arm64
make x86
docker build -t ubirch/ubirch-go-udp-client:amd64 .
docker push ubirch/ubirch-go-udp-client:amd64
cat << EOF > template.yaml
image: ubirch/ubirch-go-udp-client:latest
manifests:
  - image: ubirch/ubirch-go-udp-client:amd64
    platform:
      architecture: amd64
      features:
        - sse
      os: linux
  - image: ubirch/ubirch-go-udp-client:arm64
    platform:
      architecture: arm64
      os: linux
EOF
./manifest-tool-linux-amd64 push from-spec template.yaml