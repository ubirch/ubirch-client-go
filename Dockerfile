FROM debian:latest AS ssl
RUN \
    apt-get update -yq && \
    apt-get install -yq ca-certificates
FROM scratch
VOLUME /data
EXPOSE 8080/tcp
EXPOSE 15001/udp
EXPOSE 15002/udp
COPY --from=ssl /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY main/ubirch-go-client ubirch-go-client
ENTRYPOINT ["/ubirch-go-client", "/data/"]