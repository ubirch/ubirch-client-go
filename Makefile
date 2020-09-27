# Copyright 2020 UBIRCH GmbH
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

NAME=ubirch-client
DOCKER_IMAGE=ubirch/$(NAME)
DOCKER_TAG:=latest # name of the tag that will be used
DOCKER_TAG_LATEST:=false # should the 'latest' also tag be updated?

VERSION=$(shell git describe --tags --match 'v[0-9]*' --dirty='+d' --always)
REVISION=$(shell git rev-parse HEAD)$(shell if ! git diff --no-ext-diff --quiet --exit-code; then echo +d; fi)

GO=go
LDFLAGS=-ldflags "-buildid= -s -w -X main.Version=$(VERSION)"
GO_BUILD=$(GO) build -tags="netgo" -trimpath $(LDFLAGS)
DOCKER=DOCKER_CLI_EXPERIMENTAL=enabled docker
UPX=upx --quiet --quiet

binaries: build/$(NAME).linux_amd64
binaries: build/$(NAME).linux_arm
binaries: build/$(NAME).linux_arm64
binaries: build/$(NAME).windows_amd64.exe

images: build/docker-$(NAME)-amd64.tar
images: build/docker-$(NAME)-arm32v7.tar
images: build/docker-$(NAME)-arm64v8.tar

all: binaries images

docker: docker.amd64
docker: docker.arm32v7
docker: docker.arm64v8

# Oh boy, here we go..
dockerhub: docker
#   The manifest-tool is not able to work if the images are not already
#   Pushed to a remote docker repository!
#   We are also not able to set the architecture of the tags at this time,
#   so they will be treated as AMD64 and clutter the tags list.
	$(DOCKER) push $(DOCKER_IMAGE):amd64
	$(DOCKER) push $(DOCKER_IMAGE):arm32v7
	$(DOCKER) push $(DOCKER_IMAGE):arm64v8
#   removing manifests is neccessary, otherwise the manifest-tool will
#   get stuck with no way of creating new manifests with the same name as
#   existing ones.
	rm ~/.docker/manifests -rf
#   First we create the new manifest, inserting all the tags into it.
#   Note that their architecture will still be referred as "amd64" at
#   this point.
	$(DOCKER) manifest create $(DOCKER_IMAGE):$(DOCKER_TAG) \
		$(DOCKER_IMAGE):amd64 \
		$(DOCKER_IMAGE):arm32v7 \
		$(DOCKER_IMAGE):arm64v8
#   Now we can update the freshly created manifest, so the architecture
#   of our custom image tags are correct.
	$(DOCKER) manifest annotate --os=linux --arch=amd64 $(DOCKER_IMAGE):$(DOCKER_TAG) $(DOCKER_IMAGE):amd64
	$(DOCKER) manifest annotate --os=linux --arch=arm --variant=v7 $(DOCKER_IMAGE):$(DOCKER_TAG) $(DOCKER_IMAGE):arm32v7
	$(DOCKER) manifest annotate --os=linux --arch=arm64  --variant=v8 $(DOCKER_IMAGE):$(DOCKER_TAG) $(DOCKER_IMAGE):arm64v8
#   Finally we push it, creating a new multi-arch tag on the dockerhub.
	$(DOCKER) manifest push $(DOCKER_IMAGE):$(DOCKER_TAG)
#   Do we also need to update the 'latest' tag?
ifeq ($(DOCKER_TAG_LATEST), true)
#   As we have no way of copying this manifest, we need to do it all
#   over again.
	$(DOCKER) manifest create $(DOCKER_IMAGE):latest \
		$(DOCKER_IMAGE):amd64 \
		$(DOCKER_IMAGE):arm32v7 \
		$(DOCKER_IMAGE):arm64v8
	$(DOCKER) manifest annotate --os=linux --arch=amd64 $(DOCKER_IMAGE):latest $(DOCKER_IMAGE):amd64
	$(DOCKER) manifest annotate --os=linux --arch=arm --variant=v7 $(DOCKER_IMAGE):latest $(DOCKER_IMAGE):arm32v7
	$(DOCKER) manifest annotate --os=linux --arch=arm64  --variant=v8 $(DOCKER_IMAGE):latest $(DOCKER_IMAGE):arm64v8
	$(DOCKER) manifest push $(DOCKER_IMAGE):latest
endif

build:
	mkdir -p build/

build/$(NAME).linux_amd64: build
	cd main; CGO=0 GOOS=linux GOARCH=amd64 $(GO_BUILD) -o ../$@ .

build/$(NAME).linux_arm: build
	cd main; CGO=0 GOOS=linux GOARCH=arm GOARM=7 $(GO_BUILD) -o ../$@ .

build/$(NAME).linux_arm64: build
	cd main; CGO=0 GOOS=linux GOARCH=arm64 $(GO_BUILD) -o ../$@ .

build/$(NAME).windows_amd64.exe: build
	cd main; CGO=0 GOOS=windows GOARCH=amd64 $(GO_BUILD) -o ../$@ .

pack: binaries
	$(UPX) build/*

docker.amd64:
	$(DOCKER) build --build-arg GOARCH=amd64 -t $(DOCKER_IMAGE):amd64 .

docker.arm32v7:
	$(DOCKER) build --build-arg GOARCH=arm --build-arg GOARM=7 -t $(DOCKER_IMAGE):arm32v7 .

docker.arm64v8:
	$(DOCKER) build --build-arg GOARCH=arm64 -t $(DOCKER_IMAGE):arm64v8 .

build/docker-$(NAME)-amd64.tar: build docker.amd64
	$(DOCKER) image save --output=$@ $(DOCKER_IMAGE):amd64

build/docker-$(NAME)-arm32v7.tar: build docker.arm32v7
	$(DOCKER) image save --output=$@ $(DOCKER_IMAGE):arm32v7

build/docker-$(NAME)-arm64v8.tar: build docker.arm64v8
	$(DOCKER) image save --output=$@ $(DOCKER_IMAGE):arm64v8

clean:
	rm -r build/

.PHONY: all binaries clean pack docker docker.amd64 docker.arm32v7 docker.arm64v8
