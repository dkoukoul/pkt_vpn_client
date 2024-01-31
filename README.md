# PKT VPN Client

This Python script is a VPN client for the PKT network. It uses the cjdns protocol to establish a secure connection to a VPN server. The client supports both direct VPN connections and reverse VPN connections.

## Features

- Connect to a VPN server using the cjdns protocol.
- Request authorization from the VPN server.
- Add peers to the cjdns network.
- Check if the VPN connection is established.
- Check the status of the VPN connection.
- Request a reverse VPN port.
- Check if a specific port is available for use.
- Add a port to nftables for firewall rules.

## How it works

The script first checks if cjdns is running. If not, it starts cjdns. It then fetches a list of VPN servers and prompts the user to choose one. The user is also asked to choose a port for the reverse VPN.

The script then attempts to connect to the chosen VPN server. It adds the necessary peers, checks if the connection is established, and requests VPN authorization. If the connection is established and authorized, it connects to the VPN exit node and checks the connection status.

Once the VPN connection is established, the script requests the reverse VPN port and adds the chosen port to nftables.

The script also includes a function to authorize the VPN every hour. This function runs in an infinite loop, sleeping for an hour between each authorization attempt.

## Usage

To use this script, first set the CJDNS_PATH variable in the script to the path of your cjdns folder. 
Then simply run it with sudo:

```bash
sudo ./pktVpnClient.py
```

Follow the prompts to choose a VPN server and a port for the reverse VPN. The script will handle the rest.
