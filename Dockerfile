ARG GOVERSION=1.16
FROM golang:$GOVERSION-alpine AS builder
COPY . /app
ARG GOARCH=amd64
ARG GOARM=7
ARG VERSION=devbuild
ARG REVISION=0000000
WORKDIR /app/main
RUN \
    GOOS=linux \
    GOPROXY=https://proxy.golang.org,direct \
    go build -trimpath -ldflags "-buildid= -s -w -X main.Version=$VERSION -X main.Revision=$REVISION" -o main .


FROM debian:bullseye
VOLUME /data
EXPOSE 8080/tcp
COPY --from=builder app/main/main ubirch-client
ENTRYPOINT ["/ubirch-client"]
CMD ["/data"]
