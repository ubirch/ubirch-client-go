#!/bin/bash

if [[ ! -x "./mainfest-tool-linux-amd64" ]]; then
  echo "You are missing the mainifest-tool for tagging ARM images, you"
  echo "will need to download it before running this command".
  echo ""
  echo "if you just want to build simple binaries or docker containers,"
  echo "use 'make' instead."
  exit 1
fi

make docker.arm
make docker.x86

# Create manifest-tool template if it doesnt exist.
if [[ ! -f template.yaml ]]; then
cat <<-EOF > template.yaml
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
fi

./manifest-tool-linux-amd64 push from-spec template.yaml
