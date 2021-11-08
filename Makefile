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
REVISION = $(shell git rev-parse --short HEAD)$(shell if ! git diff --no-ext-diff --quiet --exit-code; then echo -dirty; fi)
CURRENT_BRANCH = $(shell git branch --show-current |tr -cd '[:alnum:]-.')

NAME := ubirch-client
SRC_URL = https://github.com/ubirch/ubirch-client-go.git
IMAGE_REPO := docker.io/ubirch/$(NAME)
IMAGE_TAG := $(VERSION)
IMAGE_ARCHS := amd64 arm arm64 386 # supported architectures

GO = go
GO_VERSION := 1.16
LDFLAGS = -ldflags "-buildid= -s -w -X main.Version=$(VERSION) -X main.Revision=$(REVISION)"
GO_BUILD = $(GO) build -trimpath $(LDFLAGS)
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
	$(DOCKER) build -t $(IMAGE_REPO):$(IMAGE_TAG) \
		--build-arg="VERSION=$(VERSION)" \
		--build-arg="REVISION=$(REVISION)" \
		--build-arg="GOVERSION=$(GO_VERSION)" \
		--label="org.opencontainers.image.title=$(NAME)" \
		--label="org.opencontainers.image.created=$(NOW)" \
		--label="org.opencontainers.image.source=$(SRC_URL)" \
		--label="org.opencontainers.image.version=$(VERSION)" \
		--label="org.opencontainers.image.revision=$(REVISION)" .

# Publish publishes the built image.
.PHONY: publish
publish: image
	$(DOCKER) push $(IMAGE_REPO):$(IMAGE_TAG)	

tag-stable:
	$(DOCKER) tag $(IMAGE_REPO):$(IMAGE_TAG) $(IMAGE_REPO):stable
	$(DOCKER) push $(IMAGE_REPO):stable

.PHONY: publish-branch
publish-branch: IMAGE_TAG=$(CURRENT_BRANCH)
publish-branch: publish

.PHONY: clean
clean:
	$(MAKE) clean -C main
	rm -rf build/
	$(DOCKER) image rm $(IMAGE_REPO):$(IMAGE_TAG) | true
