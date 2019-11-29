FROM alpine:3.7
RUN mkdir -p /app
RUN mkdir -p /data
COPY main/ubirch-go-client-x86 /app/ubirch-go-client
EXPOSE 8080/tcp
EXPOSE 15001/udp
EXPOSE 15002/udp
WORKDIR '/app'
ENV PATH "$PATH:/app"
ENTRYPOINT ["ubirch-go-client", "/data/"]