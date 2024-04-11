package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/zeebo/bencode"
)

var logger = logrus.New()
var reconfig = flag.Bool("reconfig", false, "Run and reset configuration")
var vpnfromconfig = flag.Bool("vpnfromconfig", false, "Set vpn server to connect to")
var nopeers = flag.Bool("nopeers", false, "Do not attempts to update cjdns peering lines")
var directauth = flag.Bool("directauth", false, "Will try to authorize directly to the server, without using the coord server")

type Cache struct {
	SelectedServer  string `json:"selectedServer"`
	ReverseVPNPorts []int  `json:"reverseVPNPorts"`
}
type Config struct {
	ServerPort              int       `json:"serverPort"`
	CjdnsPath               string    `json:"cjdnsPath"`
	ExcludedReverseVPNPorts []int     `json:"excludedReverseVPNPorts"`
	VPNServer               VPNServer `json:"vpnserver"`
	Cache                   Cache     `json:"cache"`
}

var config Config

type VPNServer struct {
	PublicKey           string   `json:"public_key"`
	Name                string   `json:"name"`
	CountryCode         string   `json:"country_code"`
	AverageRating       *float64 `json:"average_rating"` // Use pointer to float64 to allow null values
	Cost                float32  `json:"cost"`
	Load                float32  `json:"load"`
	Quality             float32  `json:"quality"`
	PublicIP            string   `json:"public_ip"`
	OnlineSinceDatetime string   `json:"online_since_datetime"`
	LastSeenDatetime    string   `json:"last_seen_datetime"`
	NumRatings          float32  `json:"num_ratings"`
	CreatedAt           string   `json:"created_at"`
	LastSeenAt          string   `json:"last_seen_at"`
	IsActive            bool     `json:"is_active"`
	AuthServer          string   `json:"auth_server"`
}

type CjdnsPeeringLine struct {
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	Login     string `json:"login"`
	Password  string `json:"password"`
	PublicKey string `json:"publicKey"`
	Name      string `json:"name"`
}

func sendUDP(message []byte) map[string]interface{} {
	cjdnsIP := "127.0.0.1"
	cjdnsPort := 11234

	conn, err := net.Dial("udp", fmt.Sprintf("%s:%d", cjdnsIP, cjdnsPort))
	if err != nil {
		fmt.Println("Error connecting to Cjdns:", err)
		return nil
	}
	defer conn.Close()

	if _, err := conn.Write(message); err != nil {
		fmt.Println("Error sending UDP message:", err)
		return nil
	}

	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		fmt.Println("Error receiving UDP message:", err)
		return nil
	}

	data := buffer[:n]
	dataStr := string(data)
	indexOfD := strings.Index(dataStr, "d")
	if indexOfD == -1 {
		fmt.Println("Invalid UDP response:", dataStr)
		return nil
	}
	strippedDataStr := "d" + dataStr[indexOfD:]
	if strings.HasPrefix(strippedDataStr, "dd") {
		strippedDataStr = strippedDataStr[1:]
	}
	strippedData := []byte(strippedDataStr)
	// fmt.Println("strippedDataStr Data:", strippedDataStr)
	// fmt.Println("Stripped Data:", string(strippedData))
	var result map[string]interface{}
	if err := bencode.DecodeBytes(strippedData, &result); err != nil {
		fmt.Println("Error decoding UDP response:", err)
		return nil
	}

	return result
}

func sign(digest []byte) map[string]interface{} {
	message := map[string]interface{}{
		"args": map[string][]byte{
			"msgHash": digest,
		},
		"q": "Sign_sign",
	}

	benc, err := bencode.EncodeBytes(message)
	if err != nil {
		fmt.Println("Error encoding message:", err)
		return nil
	}

	return sendUDP(benc)
}

type Payload struct {
	Date int `json:"date"`
}

func requestAuthorization(pubKey, signature, dateStr string) int {
	url := ""
	if *directauth {
		url = fmt.Sprintf("http://%s/api/0.3/server/authorize/", config.VPNServer.AuthServer)
	} else {
		url = fmt.Sprintf("https://vpn.anode.co/api/0.3/vpn/servers/%s/authorize/", pubKey)
	}

	date, _ := strconv.Atoi(dateStr)
	payload := &Payload{
		Date: date,
	}

	jsonData, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Println("Error creating HTTP request:", err)
		return 0
	}

	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Authorization", "cjdns "+signature)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("Error making HTTP request:", err)
		return 0
	}
	defer resp.Body.Close()

	if (resp.StatusCode == http.StatusOK) || (resp.StatusCode == http.StatusCreated) {
		fmt.Println("VPN client Authorized")
		logger.Infof("VPN Authorized: %s", pubKey)
	} else {
		fmt.Println("VPN Auth request failed with status code", resp.StatusCode)
		logger.Errorf("Request failed with status code %d and message %s", resp.StatusCode, resp.Status)
	}

	return resp.StatusCode
}

func getCjdnsPeeringLines() []CjdnsPeeringLine {
	url := "https://vpn.anode.co/api/0.4/vpn/cjdns/peeringlines/"
	headers := map[string]string{"Content-Type": "application/json"}

	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("Error creating HTTP request:", err)
		return nil
	}

	for key, value := range headers {
		req.Header.Add(key, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error making HTTP request:", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		var data []CjdnsPeeringLine
		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			fmt.Println("Error decoding JSON response:", err)
			return nil
		}
		return data
	}

	return nil
}

func addCjdnsPeer(peer CjdnsPeeringLine) {
	// Check if address is set correctly
	if net.ParseIP(peer.IP) == nil {
		fmt.Println("Invalid IPv4 address:", peer.IP)
		logger.Errorf("Invalid IPv4 address: %s", peer.IP)
		return
	}

	message := map[string]interface{}{
		"q": "UDPInterface_beginConnection",
		"args": map[string]interface{}{
			"publicKey":       peer.PublicKey,
			"address":         fmt.Sprintf("%s:%d", peer.IP, peer.Port),
			"peerName":        "",
			"password":        peer.Password,
			"login":           peer.Login,
			"interfaceNumber": 0,
		},
	}

	benc, err := bencode.EncodeBytes(message)
	if err != nil {
		fmt.Println("Error encoding message:", err)
		return
	}

	sendUDP(benc)
}

func getCjdnsSignature(data []byte) string {
	hash := sha256.Sum256(data)
	digestStr := base64.StdEncoding.EncodeToString(hash[:])
	signature := sign([]byte(digestStr))
	if signature != nil {
		if sig, ok := signature["signature"]; ok {
			if sigStr, ok := sig.(string); ok {
				return sigStr
			}
		}
	}
	fmt.Println("Cjdns signature not found")
	return ""
}

func routeGenAddException(address string) {
	message := map[string]interface{}{
		"q": "RouteGen_addException",
		"args": map[string]string{
			"route": address,
		},
	}

	benc, err := bencode.EncodeBytes(message)
	if err != nil {
		fmt.Println("Error encoding message:", err)
		return
	}

	sendUDP(benc)
}

func authorizeVPN(vpnKey string) int {
	fmt.Println("Authorizing VPN ...")
	logger.Infof("Authorizing VPN %s", vpnKey)
	now := time.Now().UnixNano() / int64(time.Millisecond)
	jsonDate, err := json.Marshal(map[string]int64{"date": now})
	if err != nil {
		fmt.Println("Error encoding JSON date:", err)
		logger.Errorf("Error encoding JSON date: %v", err)
		return 0
	}

	signature := getCjdnsSignature(jsonDate)

	if signature == "" {
		fmt.Println("Failed to get Cjdns signature")
		logger.Errorf("Failed to get Cjdns signature")
		return 0
	}

	return requestAuthorization(vpnKey, signature, fmt.Sprintf("%d", now))
}

func bencodeBytes(message map[string]interface{}) []byte {
	benc, err := bencode.EncodeBytes(message)
	if err != nil {
		fmt.Println("Error encoding message:", err)
		return nil
	}
	return benc
}

func ipTunnelConnectTo(node string) {
	fmt.Println("Connecting to VPN Exit ...")
	sendUDP(bencodeBytes(map[string]interface{}{
		"q": "IpTunnel_connectTo",
		"args": map[string]string{
			"publicKeyOfNodeToConnectTo": node,
		},
	}))
}

func checkStatus() bool {
	result, err := exec.Command("ip", "route", "get", "8.8.8.8").Output()
	if err != nil {
		logger.Errorf("status failed: %v", err)
		return false
	}
	return strings.Contains(string(result), "dev tun0")
}

func getListOfVPNServers() []VPNServer {
	url := "https://vpn.anode.co/api/0.3/vpn/servers/false/"

	response, err := http.Get(url)
	if err != nil {
		fmt.Println("Failed to fetch servers:", err)
		logger.Errorf("Failed to fetch servers: %v", err)
		return nil
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusOK {
		var servers []VPNServer
		if err := json.NewDecoder(response.Body).Decode(&servers); err != nil {
			fmt.Println("Error decoding JSON response:", err)
			return nil
		}

		return servers
	}

	fmt.Println("Failed to fetch servers:", response.StatusCode)
	logger.Errorf("Failed to fetch servers: %d", response.StatusCode)
	return nil
}

func checkConnectionEstablished(publicKey string) bool {
	// fmt.Println("Checking peerStats ...")
	connections := sendUDP(bencodeBytes(map[string]interface{}{
		"q": "InterfaceController_peerStats",
		"args": map[string]interface{}{
			"page": 0,
		},
	}))

	peers, ok := connections["peers"].([]interface{})
	if !ok {
		fmt.Println("Error parsing peers from response")
		return false
	}

	for _, peer := range peers {
		peerMap, ok := peer.(map[string]interface{})
		if !ok {
			fmt.Println("Error parsing peer map")
			continue
		}

		peerAddr, ok := peerMap["addr"].(string)
		if !ok {
			fmt.Println("Error parsing peer address")
			continue
		}
		// fmt.Println("Cjdns peer state:", peerMap["state"])
		peerKey := strings.Split(peerAddr, ".")[5] + ".k"
		// fmt.Println("Peer Key:", peerKey, "Public Key:", publicKey)
		// fmt.Println("Cjdns peer state:", peerMap["state"])
		if peerKey == publicKey {
			fmt.Println("Cjdns peer state:", peerMap["state"])
			return peerMap["state"] == "ESTABLISHED"
		}
	}

	return false
}

func connectVPNServer(publicKey, vpnExitIP, vpnName string) (string, bool) {
	fmt.Println("Connecting to", vpnName, " ...")
	if !*nopeers {
		// Assume cjdns is already running
		peers := getCjdnsPeeringLines()
		for _, peer := range peers {
			if peer.IP == vpnExitIP {
				// fmt.Println("Adding Cjdns Peer:", peer.IP)
				logger.Infof("Adding Cjdns Peer: %s", peer.IP)
				addCjdnsPeer(peer)
			}
		}
		time.Sleep(5 * time.Second)
	}
	connectionEstablished := false
	tries := 0
	for !connectionEstablished && tries < 10 {
		time.Sleep(2 * time.Second)
		connectionEstablished = checkConnectionEstablished(publicKey)
		tries++
	}

	logger.Infof("%s: Connection Established: %v", vpnName, connectionEstablished)

	// Authorize VPN
	tries = 0

	for tries < 5 {
		response := authorizeVPN(publicKey)
		if response != 200 && response != 201 {
			logger.Info("Authorization failed")
		} else {
			break
		}
		time.Sleep(5 * time.Second)
		tries++
	}

	logger.Info("Connecting cjdns tunnel ...")
	ipTunnelConnectTo(publicKey)
	routeGenAddException(vpnExitIP)
	time.Sleep(3 * time.Second)
	status := false
	tries = 0
	for !status && tries < 10 {
		time.Sleep(10 * time.Second)
		status = checkStatus()
		logger.Infof("VPN Status: %v", status)
		tries++
	}

	return publicKey, status
}

func startCjdns() {
	cjdrouteConf, err := ioutil.ReadFile(config.CjdnsPath + "cjdroute.conf")
	if err != nil {
		fmt.Println("Error reading cjdroute.conf:", err)
		logger.Errorf("Error reading cjdroute.conf: %v", err)
		os.Exit(1)
	}

	logger.Info("Starting cjdns ...")
	cmd := exec.Command("sudo", config.CjdnsPath+"cjdroute")
	cmd.Stdin = ioutil.NopCloser(strings.NewReader(string(cjdrouteConf)))

	if err := cmd.Start(); err != nil {
		fmt.Println("Error starting cjdns:", err)
		logger.Errorf("Error starting cjdns: %v", err)
		os.Exit(1)
	}

	time.Sleep(2 * time.Second) // Wait for 2 seconds for cjdns to start
}

func checkCjdnsRunning() bool {
	cmd := exec.Command("pgrep", "cjdroute")
	output, err := cmd.Output()
	if err != nil {
		logger.Info("Cjdns is not running")
		return false
	}

	if len(strings.TrimSpace(string(output))) > 0 {
		logger.Info("Cjdns is running")
		return true
	} else {
		logger.Info("Cjdns is not running")
		return false
	}
}

func promptUserforConfig() {
	logger.Info("Prompting user for config ...")
	promptUserforCjdnsPath()
	promptUserForExcludedPorts()
	servers := getListOfVPNServers()
	promptUserforServer(servers)
	promptUserforReversePort()
}

func promptUserForExcludedPorts() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("Enter the ports to be excluded, separated by commas:")
	text, _ := reader.ReadString('\n')
	text = strings.TrimSpace(text)
	ports := strings.Split(text, ",")
	for _, port := range ports {
		port = strings.TrimSpace(port)
		iport, err := strconv.Atoi(port)
		if err != nil {
			fmt.Printf("Invalid port %s\n", port)
			logger.Error("Failed to convert port to integer")
		}
		config.ExcludedReverseVPNPorts = append(config.ExcludedReverseVPNPorts, iport)
	}
}

func promptUserforCjdnsPath() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter the path to cjdroute and cjdroute.conf: ")
	text, _ := reader.ReadString('\n')
	text = strings.TrimSpace(text)
	//Make sure path ends with a backslash
	if !strings.HasSuffix(text, "/") {
		text += "/"
	}
	config.CjdnsPath = text
}

func promptUserforServer(servers []VPNServer) error {
	for i, server := range servers {
		fmt.Printf("%d. %s\n", i+1, server.Name)
	}

	var chosenIndex int
	fmt.Print("Choose a server by number: ")
	if _, err := fmt.Scan(&chosenIndex); err != nil {
		fmt.Println("Error reading input:", err)
		return err
	}

	if chosenIndex < 1 || chosenIndex > len(servers) {
		fmt.Println("Invalid server index")
		return fmt.Errorf("invalid server index")
	}
	config.Cache.SelectedServer = servers[chosenIndex-1].PublicKey
	return nil
}

func promptUserforReversePort() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Choose port(s) for reverse VPN (separate multiple values with comma or empty for none): ")
	text, _ := reader.ReadString('\n')
	text = strings.TrimSpace(text)

	if text == "" {
		return
	}
	config.Cache.ReverseVPNPorts = []int{}
	if strings.Contains(text, ",") {
		ports := strings.Split(text, ",")
		for _, port := range ports {
			port = strings.TrimSpace(port)
			port, err := strconv.Atoi(port)
			if err != nil {
				log.Fatal(err)
			}
			config.Cache.ReverseVPNPorts = append(config.Cache.ReverseVPNPorts, port)
		}
	} else {
		port, err := strconv.Atoi(text)
		if err != nil {
			log.Fatal(err)
		}
		config.Cache.ReverseVPNPorts = append(config.Cache.ReverseVPNPorts, port)
	}
}

func getCjdnsIPv4(interfaceName string) string {
	ifaces, err := net.Interfaces()
	if err != nil {
		fmt.Println("Error getting network interfaces:", err)
		logger.Errorf("Error getting network interfaces: %v", err)
		return ""
	}

	for _, iface := range ifaces {
		if iface.Name == interfaceName {
			addrs, err := iface.Addrs()
			if err != nil {
				fmt.Println("Error getting addresses for interface:", err)
				logger.Errorf("Error getting addresses for interface %s: %v", interfaceName, err)
				return ""
			}

			for _, addr := range addrs {
				ipNet, ok := addr.(*net.IPNet)
				if !ok {
					continue
				}

				if ipNet.IP.To4() != nil {
					return ipNet.IP.String()
				}
			}
		}
	}

	fmt.Printf("No IPv4 address found for %s\n", interfaceName)
	logger.Infof("No IPv4 address found for %s", interfaceName)
	return ""
}

func requestReverseVPNPort(ip string, port int) {
	fmt.Println("Requesting reverse VPN port:", port)
	url := "http://" + ip + ":8099/api/0.4/server/reversevpn/"
	payload, err := json.Marshal(map[string]interface{}{
		"port": port,
		"ip":   getCjdnsIPv4("tun0"),
	})
	if err != nil {
		fmt.Println("Error encoding JSON payload:", err)
		logger.Errorf("Error encoding JSON payload: %v", err)
		return
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
	if err != nil {
		fmt.Println("Error creating HTTP request:", err)
		logger.Errorf("Error creating HTTP request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending HTTP request:", err)
		logger.Errorf("Error sending HTTP request: %v", err)
		return
	}
	defer resp.Body.Close()

	fmt.Println("Reverse VPN response:", resp.Status)
}

func isExcludedReverseVPNPort(port int) bool {
	for _, excludedPort := range config.ExcludedReverseVPNPorts {
		if port == excludedPort {
			return true
		}
	}
	return false
}

func loadConfig(reconfig bool) error {
	_, err := os.Stat("config.json")
	if os.IsNotExist(err) || reconfig {
		if reconfig {
			//Delete existing config file
			os.Remove("config.json")
		} else {
			fmt.Println("Could not find config.json.")
			logger.Info("Could not find config.json.")
		}

		// Create the file with default values
		file, err := os.Create("config.json")
		if err != nil {
			return err
		}
		defer file.Close()

		// Prompt user for values
		promptUserforConfig()
		config.ServerPort = 8080

		data, err := json.Marshal(config)
		if err != nil {
			return err
		}

		_, err = file.Write(data)
		if err != nil {
			return err
		}

	} else if err != nil {
		return err
	} else {
		fmt.Println("Starting client with existing configuration...")
		fmt.Println("run with --reconfig if you wish to reset it.")
		fmt.Println("")
		logger.Info("Starting client with existing config.json")
	}
	file, err := os.Open("config.json")
	if err != nil {
		return err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	err = decoder.Decode(&config)
	if err != nil {
		return err
	}
	return nil
}

func main() {
	flag.Parse()
	fmt.Println("***** PKT VPN Client *****")
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	logFile, err := os.OpenFile("pktvpnclient.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err == nil {
		logger.Out = logFile
	} else {
		logger.Info("Failed to log to file, using default stderr")
	}
	logger.Info("Starting pktVpnClient ...")

	reset := false
	if *reconfig {
		reset = true
	}
	err = loadConfig(reset)
	if err != nil {
		logger.Errorf("Error loading config.json: %v", err)
		fmt.Println("Error loading config.json:", err)
		return
	}

	if !checkCjdnsRunning() {
		startCjdns()
	}
	server := VPNServer{}
	if *vpnfromconfig {
		server = config.VPNServer
	} else {
		servers := getListOfVPNServers()

		if config.Cache.SelectedServer == "" {
			promptUserforServer(servers)
		}
		for _, s := range servers {
			if s.PublicKey == config.Cache.SelectedServer {
				server = s
				break
			}
		}
		// If SelectedServer still not set, mean it is not in the list anymore
		if (server == VPNServer{}) {
			fmt.Println("VPN server not in the list of active servers. Please select another one.")
			promptUserforServer(servers)
		}
	}

	publicKey, status := connectVPNServer(server.PublicKey, server.PublicIP, server.Name)
	fmt.Println("VPN Connected Status:", status)
	// logger.Infof("VPN Status: %v", status)

	// Request reverse VPN port
	if status {
		for _, port := range config.Cache.ReverseVPNPorts {
			if !isExcludedReverseVPNPort(port) {
				requestReverseVPNPort(server.PublicIP, port)
			} else {
				fmt.Println("Port", port, "is excluded from reverse VPN, see config.json.")
				logger.Infof("Port %d is excluded from reverse VPN, see config.json.", port)
			}
		}
		for {
			// Sleep for one hour before the next authorization attempt
			time.Sleep(1 * time.Hour)
			fmt.Println("Renewing authorization...")
			logger.Info("Renewing authorization")
			tries := 0
			for tries < 5 {
				response := authorizeVPN(publicKey)
				if response != 200 && response != 201 {
					logger.Info("Authorization failed")
				} else {
					break
				}
				time.Sleep(5 * time.Second)
				tries++
			}
		}
	} else {
		fmt.Println("VPN connection failed, exiting ...")
		logger.Info("exiting...")
	}
}
