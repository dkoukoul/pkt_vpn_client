# PKT VPN Client

This is a VPN client for the PKT network. It uses the cjdns protocol to establish a secure connection to a VPN server. The client supports both direct VPN connections and requesting for reverse VPN.


## Features

- Connect to a VPN server using the cjdns protocol.
- Request authorization from the VPN server.
- Add peers to the cjdns network.
- Check if the VPN connection is established.
- Check the status of the VPN connection.
- Request a reverse VPN port.

## Usage


```bash
go install github.com/dkoukoul/pkt_vpn_client
```

Then run it:

```bash
pkt_vpn_client
```

To reset configuration either edit config.json or:
```bash
pkt_vpn_client --reconfig
```
