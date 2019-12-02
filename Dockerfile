FROM scratch
VOLUME /data
EXPOSE 8080/tcp
EXPOSE 15001/udp
EXPOSE 15002/udp
COPY main/ubirch-go-client ubirch-go-client
ENTRYPOINT ["/ubirch-go-client", "/data/"]