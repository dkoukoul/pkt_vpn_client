package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/zeebo/bencode"
)

var AUTHORIZED = false

type Config struct {
	CjdnsPath               string `json:"cjdnsPath"`
	ExcludedReverseVPNPorts []int  `json:"excludedReverseVPNPorts"`
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
	url := fmt.Sprintf("https://vpn.anode.co/api/0.3/vpn/servers/%s/authorize/", pubKey)

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

	if resp.StatusCode == http.StatusOK {
		fmt.Println("VPN client Authorized")
		//logger.Infof("VPN Authorized: %s", pubKey)
		AUTHORIZED = true
	} else {
		fmt.Println("VPN Auth request failed with status code", resp.StatusCode)
		fmt.Println("Response:", resp.Status)
		//logger.Infof("Request failed with status code %d", resp.StatusCode)
		AUTHORIZED = false
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
		//logger.Errorf("Invalid IPv4 address: %s", peer.IP)
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
	now := time.Now().UnixNano() / int64(time.Millisecond)
	jsonDate, err := json.Marshal(map[string]int64{"date": now})
	if err != nil {
		fmt.Println("Error encoding JSON date:", err)
		return 0
	}
	// fmt.Println("JSON Date:", string(jsonDate))
	signature := getCjdnsSignature(jsonDate)
	// fmt.Println("Cjdns signature:", signature)
	if signature == "" {
		fmt.Println("Failed to get Cjdns signature")
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
		//logger.Errorf("status failed: %v", err)
		return false
	}
	return strings.Contains(string(result), "dev tun0")
}

func getVPNServers() *VPNServer {
	url := "https://vpn.anode.co/api/0.3/vpn/servers/false/"

	response, err := http.Get(url)
	if err != nil {
		fmt.Println("Failed to fetch servers:", err)
		// logger.Errorf("Failed to fetch servers: %v", err)
		return nil
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusOK {
		var servers []VPNServer
		if err := json.NewDecoder(response.Body).Decode(&servers); err != nil {
			fmt.Println("Error decoding JSON response:", err)
			return nil
		}

		for i, server := range servers {
			fmt.Printf("%d. %s\n", i+1, server.Name)
		}

		var chosenIndex int
		fmt.Print("Choose a server by number: ")
		if _, err := fmt.Scan(&chosenIndex); err != nil {
			fmt.Println("Error reading input:", err)
			return nil
		}

		if chosenIndex < 1 || chosenIndex > len(servers) {
			fmt.Println("Invalid server index")
			return nil
		}

		return &servers[chosenIndex-1]
	}

	fmt.Println("Failed to fetch servers:", response.StatusCode)
	// logger.Errorf("Failed to fetch servers: %d", response.StatusCode)
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
	// Assume cjdns is already running
	peers := getCjdnsPeeringLines()
	for _, peer := range peers {
		if peer.IP == vpnExitIP {
			fmt.Println("Adding Cjdns Peer:", peer.IP)
			addCjdnsPeer(peer)
		}
	}

	time.Sleep(5 * time.Second)
	connectionEstablished := false
	tries := 0
	for !connectionEstablished && tries < 10 {
		time.Sleep(2 * time.Second)
		// fmt.Println("Checking if connection is established for ", publicKey)
		connectionEstablished = checkConnectionEstablished(publicKey)
		tries++
	}

	// logger.Infof("%s: Connection Established: %v", vpnName, connectionEstablished)

	// Authorize VPN
	tries = 0
	for !AUTHORIZED && tries < 5 {
		response := authorizeVPN(publicKey)
		if response != 200 && response != 201 {
			//fmt.Println("Abort testing for this VPN Server.")
			// logger.Info("Abort connection...")
		}

		time.Sleep(5 * time.Second)
		tries++
	}

	fmt.Println("Connecting cjdns tunnel ...")
	ipTunnelConnectTo(publicKey)
	routeGenAddException(vpnExitIP)
	time.Sleep(3 * time.Second)
	status := false
	tries = 0
	for !status && tries < 10 {
		time.Sleep(10 * time.Second)
		status = checkStatus()
		tries++
	}

	return publicKey, status
}

func authorizeVPNEveryHour(publicKey string) {
	for {
		time.Sleep(time.Hour)
		if !checkCjdnsRunning() {
			startCjdns()
		}

		tries := 0
		for !AUTHORIZED && tries < 5 {
			response := authorizeVPN(publicKey)
			if response != 200 && response != 201 {
				fmt.Println("Abort testing for this VPN Server.")
				// logger.Info("Abort connection...")
			}

			time.Sleep(5 * time.Second)
			tries++
		}
	}
}

func startCjdns() {

	cjdrouteConf, err := ioutil.ReadFile(config.CjdnsPath + "cjdroute.conf")
	if err != nil {
		fmt.Println("Error reading cjdroute.conf:", err)
		return
	}

	fmt.Println("Starting cjdns ...")
	cmd := exec.Command(config.CjdnsPath + "cjdroute")
	cmd.Stdin = ioutil.NopCloser(strings.NewReader(string(cjdrouteConf)))

	if err := cmd.Start(); err != nil {
		fmt.Println("Error starting cjdns:", err)
		return
	}

	time.Sleep(2 * time.Second) // Wait for 2 seconds for cjdns to start
}

func checkCjdnsRunning() bool {
	cmd := exec.Command("pgrep", "cjdroute")
	output, err := cmd.Output()
	if err != nil {
		fmt.Println("Error checking if Cjdns is running:", err)
		return false
	}

	if len(strings.TrimSpace(string(output))) > 0 {
		fmt.Println("Cjdns is running")
		return true
	} else {
		fmt.Println("Cjdns is NOT running")
		return false
	}
}

func askPort() int {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Choose a port for reverse VPN (empty to skip): ")
	text, _ := reader.ReadString('\n')
	text = strings.TrimSpace(text)
	fmt.Println(text)
	if text == "" {
		return 0
	}
	port, err := strconv.Atoi(text)
	if err != nil {
		log.Fatal(err)
	}
	return port
}

func askYesNo(question string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(question + " ")
	answer, _ := reader.ReadString('\n')
	return strings.TrimSpace(answer)
}

func getCjdnsIPv4(interfaceName string) string {
	ifaces, err := net.Interfaces()
	if err != nil {
		fmt.Println("Error getting network interfaces:", err)
		// logger.Errorf("Error getting network interfaces: %v", err)
		return ""
	}

	for _, iface := range ifaces {
		if iface.Name == interfaceName {
			addrs, err := iface.Addrs()
			if err != nil {
				fmt.Println("Error getting addresses for interface:", err)
				// logger.Errorf("Error getting addresses for interface %s: %v", interfaceName, err)
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
	// logger.Infof("No IPv4 address found for %s", interfaceName)
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
		// logger.Errorf("Error encoding JSON payload: %v", err)
		return
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
	if err != nil {
		fmt.Println("Error creating HTTP request:", err)
		// logger.Errorf("Error creating HTTP request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending HTTP request:", err)
		// logger.Errorf("Error sending HTTP request: %v", err)
		return
	}
	defer resp.Body.Close()

	fmt.Println("Reverse VPN response:", resp.Status)
}

func isPortAvailable(port int) bool {
	command := fmt.Sprintf("netstat -tuln | grep ':%d '", port)
	cmd := exec.Command("bash", "-c", command)
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("Error checking port %d: %v\n", port, err)
		return false
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		match := regexp.MustCompile(`:(\d+)`).FindStringSubmatch(line)
		if len(match) > 1 {
			extractedPort := match[1]
			if extractedPort == strconv.Itoa(port) {
				return false
			}
		}
	}

	return true
}

func isExcludedReverseVPNPort(port int) bool {
	for _, excludedPort := range config.ExcludedReverseVPNPorts {
		if port == excludedPort {
			return true
		}
	}
	return false
}

func addPortToNFTables(port int) error {
	command := fmt.Sprintf("nft add rule ip filter INPUT tcp dport %d accept", port)
	cmd := exec.Command("sh", "-c", command)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("error executing command: %v, output: %s", err, output)
	}

	return nil
}

func loadconfig() error {
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
	log.Println("Starting PKT VPN client")

	err := loadconfig()
	if err != nil {
		fmt.Println("Error loading config.json:", err)
		return
	}

	if !checkCjdnsRunning() {
		fmt.Println("Cjdns is not running")
		startCjdns()
	}

	server := getVPNServers()
	if server != nil {
		port := 0
		for {
			port = askPort()
			if port != 0 && !isPortAvailable(port) {
				fmt.Println("This port is already allocated.")
				answer := askYesNo("Are you sure you want to use this port? (y/n)")
				if answer == "y" {
					break
				}
			} else if !isExcludedReverseVPNPort(port) {
				break
			} else {
				fmt.Println("This port cannot be used. Please choose another port.")
			}
		}

		publicKey, status := connectVPNServer(server.PublicKey, server.PublicIP, server.Name)
		fmt.Println("VPN Connected Status:", status)

		if status && port != 0 {
			requestReverseVPNPort(server.PublicIP, port)
			if err := addPortToNFTables(port); err != nil {
				fmt.Printf("Error adding port %d to nftables: %v\n", port, err)
			} else {
				fmt.Printf("Successfully added port %d to nftables\n", port)
			}
		}

		authorizeVPNEveryHour(publicKey)
	} else {
		fmt.Println("No VPN servers found.")
	}
}
