# Windows installation

1. Download the [latest release](https://github.com/ubirch/ubirch-client-go/releases)  for windows_amd64
2. Create a `config.json` file according to [Quickstart steps 1-2](https://github.com/ubirch/ubirch-client-go#quick-start)
3. Start the client: `go-client>ubirch-client.windows_amd64.exe`
4. To test, continue with the [Quickstart step 4](https://github.com/ubirch/ubirch-client-go#quick-start)

> It may be useful to run the go client as a service. You can follow [this guide](https://www.howtogeek.com/50786/using-srvstart-to-run-any-application-as-a-windows-service/)
> to install it as service.

## TODO

- Use a direct [service wrapper implementation](https://github.com/golang/sys/blob/master/windows/svc/example/service.go).
