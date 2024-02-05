import hashlib
import base64
import time
import json
import socket
import subprocess
import logging
import requests
import bencode
import re
import netifaces as ni

AUTHORIZED: bool = False

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
handler = logging.FileHandler('vpnclient.log')
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s ')
handler.setFormatter(formatter)
logger.addHandler(handler)

CJDNS_PATH = "/home/dimitris/Code/cjdns/"
excluded_reverse_vpn_ports = [22, 80, 443]

def send_udp(message):
    """Send UDP message to cjdns"""
    #print("Sending message:", message)
    cjdns_ip = "127.0.0.1"
    cjdns_port = 11234
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(message, (cjdns_ip, cjdns_port))
    data, _ = sock.recvfrom(4096)
    #print("Received message: ", data.decode('utf-8'))
    data_str = data.decode()
    index_of_d = data_str.index("d")
    stripped_data_str = "d"+data_str[index_of_d:].lstrip("d0")
    stripped_data = stripped_data_str.encode()
    return dict(bencode.bdecode(stripped_data))


def sign(digest):
    """Sign message with cjdns"""
    benc = bencode.bencode({"args": {"msgHash": digest}, "q": "Sign_sign"})
    return send_udp(benc)


def get_cjdns_signature(bytes_):
    """Get cjdns signature"""
    digest = hashlib.sha256(bytes_).digest()
    digest_str = base64.b64encode(digest).decode('utf-8')
    signature = sign(digest_str)
    #print("Cjdns signature:", signature['signature'])
    return signature['signature']


def request_authorization(pubkey, signature, date):
    """Request VPN authorization"""
    global AUTHORIZED
    url = "https://vpn.anode.co/api/0.3/vpn/servers/"+pubkey+"/authorize/"
    #payload = json.dumps({"date":date}).replace(" ", "")
    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "Authorization": "cjdns "+signature
        }
    status_code = 0
    try:
        response = requests.post(url, json={"date":date}, headers=headers, timeout=10)
        status_code = response.status_code
        if response.status_code == 200:
            AUTHORIZED = True
            print("VPN client Authorized")
            logger.info("VPN Authorized: %s", pubkey)
            #print(response.json())
        else:
            AUTHORIZED = False
            print("VPN Auth request failed with status code", response.status_code)
            logger.info("Request failed with status code %s", str(response.status_code))
    except requests.exceptions.RequestException as err:
        print("Request failed with exception", err)
        logger.info("Request failed with exception %s", str(err))

    return status_code


def get_cjdns_peering_lines() -> list:
    """Get Cjdns Peering Lines"""
    url = "https://vpn.anode.co/api/0.4/vpn/cjdns/peeringlines/"
    headers = {"Content-Type": "application/json"}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            peers = []
            for entry in data:
                peer = {
                    "ip": entry["ip"],
                    "port": entry["port"],
                    "login": entry["login"],
                    "password": entry["password"],
                    "publicKey": entry["publicKey"],
                    "name": entry["name"]
                }
                peers.append(peer)
            return peers
        else:
            return []
    except requests.exceptions.RequestException as err:
        #print("Request failed with exception", err)
        logger.exception("Request failed with exception %s", str(err))
        return []


def add_cjdns_peer(peer):
    """Add Cjdns Peer"""
    #Check if address is set correctly
    try:
        socket.inet_aton(peer["ip"])
    except socket.error:
        #print("Invalid IPv4 address:", peer["ip"])
        logger.exception("Invalid IPv4 address: %s", peer["ip"])
    else:
        benc = bencode.bencode({"q": "UDPInterface_beginConnection", "args": {
            "publicKey":peer["publicKey"],
            "address":peer["ip"]+":"+str(peer["port"]),
            "peerName":"",
            "password":peer["password"],
            "login":peer["login"],
            "interfaceNumber":0}})
        send_udp(benc)


def routegen_add_exception(address):
    """Add RouteGen Exception"""
    #print("Adding RouteGen Exception for ", address, " ...")
    send_udp(bencode.bencode({"q": "RouteGen_addException", "args": {"route": address}}))


def authorize_vpn(vpn_key: str):
    """Authorize VPN"""
    print("Authorizing VPN ...")
    now = int( time.time_ns() / 1000000)
    json_date = json.dumps({"date":now})#.replace(" ", "")
    signature = get_cjdns_signature(json_date.encode('utf-8'))
    #print("Cjdns signature:", signature)
    return request_authorization(vpn_key, signature, now)


def ip_tunnel_connect_to(node):
    """Connect to VPN Exit Node"""
    #print("Connecting to VPN Exit Node", node, " ...")
    send_udp(bencode.bencode({"q": "IpTunnel_connectTo", "args":
        {"publicKeyOfNodeToConnectTo": node}}))

def ip_tunnel_list_connections():
    """List IpTunnel Connections"""
    send_udp(bencode.bencode({"q": "IpTunnel_listConnections"}))


def check_status() -> bool:
    """Check VPN Status"""
    try:
        result = subprocess.check_output(["ip", "route", "get", "8.8.8.8"]).decode("utf-8")
        if "dev tun0" in result:
            return True
        else:
            #logger.info("status: %s", result)
            return False
    except subprocess.CalledProcessError as error:
        logger.exception("status failed: %s", error.output)
        #print(error.output)
        return False



def get_vpn_servers() -> any:
    """Get VPN Servers"""
    try:
        response = requests.get("https://vpn.anode.co/api/0.3/vpn/servers/false/", timeout=10)
        if response.status_code == 200:
            servers = response.json()
            i = 1
            for server in servers:
                servername = server["name"]
                print(f"{i}. {servername}")
                i += 1
            chosen_index = int(input("Choose a server by number: ")) - 1
            return servers[chosen_index]
        else:
            print("Failed to fetch servers: ", response.status_code)
            return None
    except requests.exceptions.HTTPError as err:
        #print("Unexpected resulting status code: ", err)
        logger.exception("Unexpected resulting status code: %s", str(err))
        return None


def check_connection_established(public_key) -> bool:
    """Check Connection Established"""
    logger.info("Checking peerStats...")
    connections = send_udp(bencode.bencode({"q": "InterfaceController_peerStats",
                                            "args": {"page":0}}))
    for peer in connections["peers"]:
        peer_key = str(peer["addr"]).split(".")[5]+".k"
        if peer_key == public_key:
            print("Cjdns peer state: ", peer["state"])
            logger.info("Connection: %s", peer["state"])
            if peer["state"] == "ESTABLISHED":
                return True
            else:
                return False
    return False


def connect_vpn_server(public_key, vpn_exit_ip, vpn_name):
    """
    This function attempts to connect to a VPN server. 
    It first adds the necessary peers, then checks if the 
    connection is established. If the connection is not established
    after 10 tries, it aborts. If the connection is established, 
    it attempts to authorize the VPN. If authorization fails after 5 tries, it aborts. If 
    authorization is successful, it connects to the VPN exit node 
    and checks the connection status. If the connection status is not successful
    after 10 tries, it aborts. If the connection status is successful, it 
    calls the function to authorize the VPN every hour.

    Parameters:
    public_key (str): The public key used for VPN authorization.
    vpn_exit_ip (str): The IP address of the VPN exit node.
    vpn_name (str): The name of the VPN.

    Returns:
    public_key (str): The public key used for VPN authorization.
    status (bool): The status of the VPN connection.
    """
    global AUTHORIZED
    print("Connecting to ", vpn_name, "...")
    # Do not test if server_name does not start with "PKT Pal"
    # if not vpn_name.startswith("PKT Pal") or not vpn_name.startswith("Test"):
    #     print("Skipping VPN Server: ", vpn_name)
    #     return
    # Launch Cjdns
    #start_cjdns() # Assume cjdns is already running
    #time.sleep(2)
    # Add Cjdns Peers
    peers = get_cjdns_peering_lines()
    for peer in peers:
        if peer["ip"] == vpn_exit_ip:
            print("Adding Cjdns Peer: ", peer["ip"])
            add_cjdns_peer(peer)

    time.sleep(5)
    connection_established = False
    tries = 0
    while (not connection_established) and (tries < 10):
        time.sleep(2)
        print("Checking if connection is established...")
        connection_established = check_connection_established(public_key)
        tries = tries + 1

    logger.info("%s: Connection Established: %s", vpn_name, connection_established)

    # Authorize VPN
    tries = 0
    while(not AUTHORIZED) and (tries < 5):
        response = authorize_vpn(public_key)
        if response != 200 and response != 201:
            #print("Abort testing for this VPN Server.")
            logger.info("Abort connection...")

        time.sleep(5)
        tries = tries + 1

    # Get Iptunnel connections
    #ip_tunnel_list_connections()
    #time.sleep(2)
    # Connect to VPN Exit Node
    print("Connecting ip tunnel...")
    ip_tunnel_connect_to(public_key)
    routegen_add_exception(vpn_exit_ip)
    time.sleep(3)
    status = False
    tries = 0
    while (not status) and (tries < 10):
        time.sleep(10)
        #status = check_public_ip(vpn_exit_ip)
        status = check_status()
        tries = tries + 1

    return public_key, status


def authorize_vpn_every_hour(public_key: str):
    """
    This function attempts to authorize the VPN every hour. 
    If authorization fails, it will retry up to 5 times
    before aborting the connection for the current hour.
    It will then sleep for an hour before attempting to 
    authorize again.

    Parameters:
    public_key (str): The public key used for VPN authorization.

    Returns:
    None
    """
    while True:
        time.sleep(3600)
        if not check_cjdns_running():
            start_cjdns()
            
        tries = 0
        while(not AUTHORIZED) and (tries < 5):
            response = authorize_vpn(public_key)
            if response != 200 and response != 201:
                #print("Abort testing for this VPN Server.")
                logger.info("Abort connection...")

            time.sleep(5)
            tries = tries + 1

def start_cjdns():
    """Start Cjdns"""
    with open(CJDNS_PATH+"cjdroute.conf", "r", encoding="utf-8") as file:
        cjdroute_conf = file.read()

    # Start cjdroute
    print("Starting cjdns...")
    logger.info("Starting cjdns...")
    process = subprocess.Popen([CJDNS_PATH+"cjdroute"],
                               stdin=subprocess.PIPE,
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
    process.communicate(input=cjdroute_conf.encode())
    time.sleep(2)


def check_cjdns_running() -> bool:
    """Check if Cjdns is running"""
    try:
        result = subprocess.check_output(["pgrep", "cjdroute"]).decode("utf-8")
        if result:
            print("Cjdns is running...")
            return True
        else:
            print("Cjdns is NOT running...")
            return False
    except subprocess.CalledProcessError as error:
        logger.exception("status failed: %s", error.output)
        return False

def get_cjdns_ipv4(interface):
    try:
        ipv4 = ni.ifaddresses(interface)[ni.AF_INET][0]['addr']
    except ValueError:
        print(f"No IPv4 address found for {interface}")
        return None
    return ipv4

def request_reverse_vpn_port(ip: str, port: int):
    """Request Reverse VPN Port"""
    print("Requesting reverse VPN port: ", port)
    url = "http://"+ip+":8099/api/0.4/server/reversevpn/"
    headers = {
        "Content-Type": "application/json; charset=utf-8"
    }
    # Get local 10.xx.xx.xx ip
    cjdns_ip = get_cjdns_ipv4("tun0")

    response = requests.post(url, json={"port":port, "ip":cjdns_ip}, headers=headers, timeout=10)
    print("Reverse VPN response: "+str(response.status_code) + " " + response.text)


def is_port_available(port: int) -> bool:
    """Check if port is available"""
    command = f"netstat -tuln | grep :{port} "
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate()

    if error:
        print(f"Error checking port {port}: {error}")
        return False
    # Decode output from bytes to string and split it into lines
    lines = output.decode().split('\n')
    for line in lines:
        # Use a regular expression to extract the port number
        match = re.search(r':(\d+)', line)
        if match:
            extracted_port = int(match.group(1))
            if extracted_port == port:
                return False

    return True


def main():
    """Maing Function"""
    logger.info("Starting PKT VPN client")
    if not check_cjdns_running():
        print("Cjdns is not running...")
        start_cjdns()


    server = get_vpn_servers()
    if server:
        while True:
            port = int(input("Choose a port for reverse VPN: "))
            # Check if port is available
            if not is_port_available(port):
                print("This port is already allocated.")
                answer = input("Are you sure you want to use this port? (y/n)")
                if answer == "y":
                    break
                else:
                    continue
            elif port not in excluded_reverse_vpn_ports:
                break
            else:
                print("This port can not be used. Please choose another port.")

        public_key, status = connect_vpn_server(server["public_key"], server["public_ip"], server["name"])
        print("VPN Connected Status: ", status)
        
        # Once we are connected we can request the Reverse VPN port
        if status:
            request_reverse_vpn_port(server["public_ip"],port)
            # Add port to nftables
            command = f"nft add rule ip filter INPUT tcp dport {port} accept"
            process = subprocess.Popen(command.split(), stdout=subprocess.PIPE)
            _, error = process.communicate()
            if error:
                print(f"Error adding port {port} to nftables: {error}")
            else:
                print(f"Successfully added port {port} to nftables")
        else:
            print("VPN Connection failed. Aborting...")

        authorize_vpn_every_hour(public_key)
    else:
        print("No VPN servers found.")


if __name__ == '__main__':
    main()
