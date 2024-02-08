# PKT VPN Client

This is a VPN client for the PKT network for Linux. It uses the cjdns protocol to establish a secure connection to a VPN server. The client supports both direct VPN connections and reverse VPN connections.
You can use the python or the Go version.

## Features

- Connect to a VPN server using the cjdns protocol.
- Request authorization from the VPN server.
- Add peers to the cjdns network.
- Check if the VPN connection is established.
- Check the status of the VPN connection.
- Request a reverse VPN port (available only on a test server currently).
- Check if a specific port is available for use.
- Add a port to nftables for firewall rules.

## How it works

First edit the path to your cjdns folder. 
  * For the Python script edit it inside the script
  * For Go use the config.json

The app first checks if cjdns is running. If not, it starts cjdns. It then fetches a list of VPN servers and prompts the user to choose one. The user is also asked to choose a port for the reverse VPN.

The app then attempts to connect to the chosen VPN server. It adds the necessary peers, checks if the connection is established, and requests VPN authorization. If the connection is established and authorized, it connects to the VPN exit node and checks the connection status.

Once the VPN connection is established, the script requests the reverse VPN port and adds the chosen port to nftables (Linux specific).

The script also includes a function to authorize the VPN every hour. This function runs in an infinite loop, sleeping for an hour between each authorization attempt.

## Usage

### Python
To use this script, first edit the CJDNS_PATH variable in the script to the path of your cjdns folder. 
Set up venv with:

```bash
./create_venv.sh
```

Then run the script:

```bash
./runPktVpnClient.sh
```
### Golang

```bash
go build -o PktVpnClient
```
```bash
./PktVpnClient
```
Follow the prompts to choose a VPN server and a port for the reverse VPN. The script will handle the rest.

## Notes
This is under development.
  * When you exit the app, cjdroute keep running, to exit the VPN you will need to exit cjdroute.
  * The reverse vpn port request currently is under testing and only availably on Test server, skip it.
