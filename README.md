# ubirch-go-udp-client

UDP client example that reads messages from multiple devices
and creates ubirch-protocol secured messages.

This server handles keys and state.

### Issues

- The configuration from console.demo.ubirch.com sets the msgpack endpoint for 
  key registration. **Remove the `/mpack` from the end of the keyService URL!**
  