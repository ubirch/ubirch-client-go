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

DOCKER = DOCKER_CLI_EXPERIMENTAL=enabled DOCKER_BUILDKIT=1 docker
THISDIR = $(dir $(realpath $(firstword $(MAKEFILE_LIST))))

NAME := ubirch-client
SRC_URL = https://gitlab.com/ubirch/ubirch-client-go.git

GO = go
GO_VERSION := 1.19
LDFLAGS = -ldflags "-buildid= -s -w -X main.Version=$(VERSION) -X main.Revision=$(REVISION)"
GO_BUILD = $(GO) build -tags="netgo" -trimpath $(LDFLAGS)
UPX=upx --quiet --quiet

.PHONY: build
build: binaries

binaries: build/bin/$(NAME).linux_amd64
binaries: build/bin/$(NAME).linux_arm
binaries: build/bin/$(NAME).linux_arm64
binaries: build/bin/$(NAME).linux_386
binaries: build/bin/$(NAME).windows_amd64.exe
build/bin/$(NAME).linux_amd64:
	CGO=0 GOOS=linux GOARCH=amd64 $(GO_BUILD) -o $@ .
build/bin/$(NAME).linux_arm:
	CGO=0 GOOS=linux GOARCH=arm GOARM=7 $(GO_BUILD) -o $@ .
build/bin/$(NAME).linux_arm64:
	CGO=0 GOOS=linux GOARCH=arm64 $(GO_BUILD) -o $@ .
build/bin/$(NAME).linux_386:
	CGO=0 GOOS=linux GOARCH=386 $(GO_BUILD) -o $@ .
build/bin/$(NAME).windows_amd64.exe:
	CGO=0 GOOS=windows GOARCH=amd64 $(GO_BUILD) -o $@ .

pack: binaries
	$(UPX) build/bin/*

.PHONY: test
test:
	$(DOCKER) run -t --rm -v $(THISDIR):/app -w /app golang:$(GO_VERSION) \
	go test ./... -short

.PHONY: clean
clean:
	rm -rf build/

