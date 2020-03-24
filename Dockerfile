FROM golang:1.13 AS builder
COPY . /app
ARG GOARCH=amd64
WORKDIR /app/main
RUN \
    CGO_ENABLED=0 \
    GOOS=linux \
    GOPROXY=https://proxy.golang.org,direct \
    go build -o main .


FROM scratch
VOLUME /data
EXPOSE 8080/tcp
EXPOSE 15001/udp
EXPOSE 15002/udp
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder app/main/main ubirch-go-client
ENTRYPOINT ["/ubirch-go-client", "/data/"]