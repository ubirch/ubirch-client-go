FROM golang:1.15 AS builder
COPY . /app
ARG GOARCH=amd64
ARG GOARM=7
WORKDIR /app/main
RUN \
    CGO_ENABLED=0 \
    GOOS=linux \
    GOPROXY=https://proxy.golang.org,direct \
    go build -trimpath -ldflags="-buildid= -s -w -linkmode external -extldflags -static" -o main .


FROM scratch
VOLUME /data
EXPOSE 8080/tcp
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder app/main/main ubirch-client
ENTRYPOINT ["/ubirch-client"]
CMD ["/data"]