#!/usr/bin/env bash
cd main
GOOS=linux CGO_ENABLED=0 GOARCH=arm go build
