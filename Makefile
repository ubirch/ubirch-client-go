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

.DEFAULT_GOAL := build
# This is a makefile for Go projects, version 1.0.0.
# The following targets of the makefile are called by the CI automatically:
# - lint:
#   checks code for obvious errors and reports them to the developer
# - build:
#   builds the artifacts of this repository
# - test:
#   runs the defined tests, optionally generates a coverage report
# - publish:
#   publishes the built artifacts to a remote repository
# - publish-branch:
#   publishes the build artifacts, but tags them with the branch name,
#   so they can be referenced for development.

NOW = $(shell date -u -Iminutes)
VERSION = $(shell git describe --tags --match 'v[0-9]*' --dirty='-dirty' --always)
REVISION = $(shell git rev-parse --short=9 HEAD)$(shell if ! git diff --no-ext-diff --quiet --exit-code; then echo -dirty; fi)
CURRENT_BRANCH = $(shell git branch --show-current |tr -cd '[:alnum:]-.')

NAME := ubirch-client
SRC_URL = https://github.com/ubirch/ubirch-client-go.git
IMAGE_REPO := docker.io/ubirch/$(NAME)
IMAGE_TAG := $(VERSION)
IMAGE_ARCHS := amd64 arm arm64 386 # supported architectures

GO = go
GO_VERSION := 1.19
LDFLAGS = -ldflags "-buildid= -s -w -X main.Version=$(VERSION) -X main.Revision=$(REVISION)"
GO_BUILD = $(GO) build -tags="netgo" -trimpath $(LDFLAGS)
UPX=upx --quiet --quiet
DOCKER = DOCKER_CLI_EXPERIMENTAL=enabled DOCKER_BUILDKIT=1 docker
GO_LINTER_IMAGE = golangci/golangci-lint:v1.32.1
THISDIR = $(dir $(realpath $(firstword $(MAKEFILE_LIST))))

.PHONY: lint
lint:
	@# we supress echoing the command, so every output line
	@# can be considered a linting error. 
	@$(DOCKER) run --rm -v $(THISDIR):/app:ro -w /app $(GO_LINTER_IMAGE) golangci-lint run

.PHONY: build
build:
	$(MAKE) build -C main

.PHONY: pack
pack:
	$(MAKE) pack -C main

.PHONY: test
test:
	$(DOCKER) run -t --rm -v $(THISDIR):/app -w /app golang:$(GO_VERSION) \
	go test ./...

.PHONY: image 
image:
	$(DOCKER) build -t $(IMAGE_REPO):$(IMAGE_TAG)-arm \
	    --build-arg="GOARCH=arm" \
		--build-arg="VERSION=$(VERSION)" \
		--build-arg="REVISION=$(VERSION)" \
		--build-arg="GOVERSION=$(GO_VERSION)" \
		--label="org.opencontainers.image.title=$(NAME)" \
		--label="org.opencontainers.image.created=$(NOW)" \
		--label="org.opencontainers.image.source=$(SRC_URL)" \
		--label="org.opencontainers.image.version=$(VERSION)" \
		--label="org.opencontainers.image.revision=$(REVISION)" .

# Publish publishes the built image.
.PHONY: publish
publish:
# this would be the easy way:
# (after depending on 'image' target)
#	$(DOCKER) push $(IMAGE_REPO):$(IMAGE_TAG)
# .. but we want multi-arch images:
#	First we need to build the individual images
	@for arch in $(IMAGE_ARCHS) ; do \
		echo Building "$(IMAGE_REPO):$(IMAGE_TAG)-$${arch}" ; \
		$(DOCKER) build -t "$(IMAGE_REPO):$(IMAGE_TAG)-$${arch}" \
			--build-arg="GOARCH=$${arch}" \
			--build-arg="VERSION=$(VERSION)" \
			--build-arg="REVISION=$(VERSION)" \
			--build-arg="GOVERSION=$(GO_VERSION)" \
			--label="org.opencontainers.image.title=$(NAME)" \
			--label="org.opencontainers.image.created=$(NOW)" \
			--label="org.opencontainers.image.source=$(SRC_URL)" \
			--label="org.opencontainers.image.version=$(VERSION)" \
			--label="org.opencontainers.image.revision=$(REVISION)" . \
		; \
	done
#	The manifest-tool is not able to work if the images are not already
#	Pushed to a remote docker repository!
#	We are also not able to set the architecture of the tags at this time,
#	so they will be treated as AMD64 and clutter the tags list.
	@for arch in $(IMAGE_ARCHS) ; do \
		echo Pushing "$(IMAGE_REPO):$(IMAGE_TAG)-$${arch}" ; \
		$(DOCKER) push "$(IMAGE_REPO):$(IMAGE_TAG)-$${arch}" ;\
	done
#	removing manifests is neccessary, otherwise the manifest-tool will
#	get stuck with no way of creating new manifests with the same name as
#	existing ones.
	rm ~/.docker/manifests -rf
#	First we create the new manifest, inserting all the tags into it.
#	Note that their architecture will still be referred as "amd64" at
#	this point.
	$(DOCKER) manifest create $(IMAGE_REPO):$(IMAGE_TAG) \
		$(IMAGE_REPO):$(IMAGE_TAG)-amd64 \
		$(IMAGE_REPO):$(IMAGE_TAG)-arm \
		$(IMAGE_REPO):$(IMAGE_TAG)-arm64 \
		$(IMAGE_REPO):$(IMAGE_TAG)-386
#	Now we can update the freshly created manifest, so the architecture
#	of our custom image tags are correct.
	$(DOCKER) manifest annotate --os=linux --arch=amd64 \
		$(IMAGE_REPO):$(IMAGE_TAG) $(IMAGE_REPO):$(IMAGE_TAG)-amd64
	$(DOCKER) manifest annotate --os=linux --arch=arm --variant=v7 \
		$(IMAGE_REPO):$(IMAGE_TAG) $(IMAGE_REPO):$(IMAGE_TAG)-arm
	$(DOCKER) manifest annotate --os=linux --arch=arm64 --variant=v8 \
		$(IMAGE_REPO):$(IMAGE_TAG) $(IMAGE_REPO):$(IMAGE_TAG)-arm64
	$(DOCKER) manifest annotate --os=linux --arch=386 \
		$(IMAGE_REPO):$(IMAGE_TAG) $(IMAGE_REPO):$(IMAGE_TAG)-386
#	Finally we push it, creating a new multi-arch tag on the dockerhub.
	$(DOCKER) manifest push $(IMAGE_REPO):$(IMAGE_TAG)
	

tag-stable:
#   As we have no way of copying this manifest, we need to do it all
#   over again.
	$(DOCKER) manifest create $(IMAGE_REPO):stable \
		$(IMAGE_REPO):$(IMAGE_TAG)-amd64 \
		$(IMAGE_REPO):$(IMAGE_TAG)-arm32v7 \
		$(IMAGE_REPO):$(IMAGE_TAG)-arm64v8
	$(DOCKER) manifest annotate --os=linux --arch=amd64 \
		$(IMAGE_REPO):latest $(IMAGE_REPO):$(IMAGE_TAG)-amd64
	$(DOCKER) manifest annotate --os=linux --arch=arm --variant=v7 \
		$(IMAGE_REPO):latest $(IMAGE_REPO):$(IMAGE_TAG)-arm32v7
	$(DOCKER) manifest annotate --os=linux --arch=arm64  --variant=v8 \
		$(IMAGE_REPO):latest $(IMAGE_REPO):$(IMAGE_TAG)-arm64v8
	$(DOCKER) manifest push $(IMAGE_REPO):stable

.PHONY: publish-branch
publish-branch: IMAGE_TAG=$(CURRENT_BRANCH)
publish-branch: publish

.PHONY: clean
clean:
	$(MAKE) clean -C main
	rm -rf build/
	$(DOCKER) image rm $(IMAGE_REPO):$(IMAGE_TAG) | true
	@for arch in $(IMAGE_ARCHS) ; do \
		$(DOCKER) image rm "$(IMAGE_REPO):$(IMAGE_TAG)-$${arch}" | true ;\
	done
	echo "NOTE: some multi-arch images may not have been deleted by the target"
