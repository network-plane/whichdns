// Package main implements a DNS server detection tool that captures network packets
// to identify which DNS server responds to DNS queries.
package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/user"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/spf13/cobra"
)

const (
	appversion     = "1.0.3"
	captureTimeout = 10 * time.Second
)

// AF_PACKET constants
const (
	afPacket = syscall.AF_PACKET
	sockRaw  = syscall.SOCK_RAW
)

// Network protocol constants
const (
	ethPAll    = 0x0003 // Ethernet protocol: All packets
	ethPIPv4   = 0x0800 // Ethernet protocol: IPv4
	ipProtoUDP = 17     // IP protocol: UDP
	dnsPort    = 53     // DNS service port
)

// Packet size constants
const (
	ethHeaderLen = 14 // Ethernet header length
	ipHeaderMin  = 20 // Minimum IP header length
	udpHeaderLen = 8  // UDP header length
	ipSrcOffset  = 12 // IP source address offset in header
)

// sockaddrLl structure for AF_PACKET
type sockaddrLl struct {
	sllFamily   uint16
	sllProtocol uint16
	sllIfindex  int32
	sllHatype   uint16
	sllPkttype  uint8
	sllHalen    uint8
	sllAddr     [8]uint8
}

// Global variables
var (
	debug bool
)

// ProgressBar represents a simple textual progress bar
type ProgressBar struct {
	total     int
	current   int
	barLength int
	mu        sync.Mutex
}

// NewProgressBar initializes a new ProgressBar
func NewProgressBar(total int, barLength int) *ProgressBar {
	return &ProgressBar{
		total:     total,
		current:   0,
		barLength: barLength,
	}
}

// Advance increments the progress and renders the bar
func (p *ProgressBar) Advance() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.current++
	if p.current > p.total {
		p.current = p.total
	}
	p.Render()
}

// Render displays the current state of the progress bar
func (p *ProgressBar) Render() {
	percentage := float64(p.current) / float64(p.total) * 100
	if percentage > 100 {
		percentage = 100
	}
	filledLength := int(percentage / 100 * float64(p.barLength))
	bar := strings.Repeat("#", filledLength) + strings.Repeat("-", p.barLength-filledLength)
	fmt.Printf("\r[%s] %.2f%%", bar, percentage)
	if p.current >= p.total {
		fmt.Println()
	}
}

// Clear clears the progress bar line by overwriting it with spaces
func (p *ProgressBar) Clear() {
	// Clear the line by overwriting with spaces and carriage return
	fmt.Printf("\r%s\r", strings.Repeat(" ", 70))
}

// IncrementDuringWait increments the progress bar every second during the wait period
func (p *ProgressBar) IncrementDuringWait(duration time.Duration, done chan struct{}) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for i := 0; i < int(duration.Seconds()); i++ {
		select {
		case <-ticker.C:
			p.Advance()
		case <-done:
			return
		}
	}
}

var (
	domainFlag string
	ipOnlyFlag bool
	debugFlag  bool
)

var rootCmd = &cobra.Command{
	Use:   "whichdns",
	Short: "Find which DNS server is being used",
	Long: `A tool to detect which DNS server responds to DNS queries by capturing network packets.

This tool performs DNS lookups while monitoring network traffic to identify
which DNS server actually responds to the queries.`,
	Run: func(cmd *cobra.Command, args []string) {
		runDNSCheck()
	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Version: %s\n", appversion)
		debugLog("Printed version and exiting.")
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
	rootCmd.Flags().StringVar(&domainFlag, "domain", "example.com", "the domain for DNS lookup")
	rootCmd.Flags().BoolVar(&ipOnlyFlag, "iponly", false, "print only the IP address of the DNS server")
	rootCmd.Flags().BoolVar(&debugFlag, "debug", false, "enable debug output")
}

func runDNSCheck() {
	debug = debugFlag

	debugLog("Parsed arguments: domain=%s, ipOnly=%v, debug=%v", domainFlag, ipOnlyFlag, debugFlag)

	// Suppress log output if ipOnly is set
	if ipOnlyFlag {
		log.SetOutput(os.Stderr)
		log.SetFlags(0)
		debugLog("ipOnly flag is set; logging output suppressed.")
	}

	// Define total steps and total progress units
	totalSteps := 9                                 // Total number of steps before wait
	timeoutSeconds := int(captureTimeout.Seconds()) // Timeout in seconds
	totalProgress := totalSteps + timeoutSeconds    // Total progress units (9 +10=19)

	// Initialize ProgressBar if not in debug mode
	var progressBar *ProgressBar
	if !debug {
		progressBar = NewProgressBar(totalProgress, 50) // 50 characters bar length
		progressBar.Render()                            // Initialize the progress bar
	}

	// Step 1: Check for root privileges
	if !isRoot() {
		if !ipOnlyFlag {
			fmt.Fprintln(os.Stderr, "This program requires root privileges to run.")
			fmt.Fprintln(os.Stderr, "Please run it as root or with sudo.")
			debugLog("User does not have root privileges.")
		}
		if progressBar != nil {
			progressBar.Advance()
		}
		os.Exit(1)
	}
	debugLog("User has root privileges.")
	if progressBar != nil {
		progressBar.Advance()
	}

	// Step 2: Get the default network interface
	iface := getDefaultNetworkInterface(!ipOnlyFlag, progressBar)
	if !ipOnlyFlag && !debug {
		progressBar.Clear()
		fmt.Printf("Default interface: %v\n", iface.Name)
		progressBar.Render() // Restart progress bar on new line
	}
	debugLog("Default network interface obtained: %v", iface.Name)

	// Step 3: Open AF_PACKET socket
	if progressBar != nil {
		progressBar.Advance()
	}
	fd, err := openAFPacketSocket(iface)
	if err != nil {
		log.Printf("Failed to open AF_PACKET socket: %v", err)
		debugLog("Failed to open AF_PACKET socket: %v", err)
		if progressBar != nil {
			progressBar.Advance()
		}
		os.Exit(1)
	}
	defer func() {
		syscall.Close(fd)
		debugLog("AF_PACKET socket closed.")
		if progressBar != nil && progressBar.current < progressBar.total {
			progressBar.Advance()
		}
	}()

	// Step 4: Skip BPF filter setup (we'll filter in userspace)
	if progressBar != nil {
		progressBar.Advance()
	}
	debugLog("AF_PACKET socket opened, filtering DNS packets in userspace.")

	// Step 5: Start packet processing
	if progressBar != nil {
		progressBar.Advance()
	}
	dnsResponseCh := make(chan string)
	errorCh := make(chan error)

	go func() {
		debugLog("Starting packet processing goroutine.")
		startTime := time.Now()
		for {
			// Check if we've exceeded the timeout
			if time.Since(startTime) > captureTimeout {
				errorCh <- fmt.Errorf("packet capture timeout")
				return
			}

			frame, err := readPacket(fd)
			if err != nil {
				errorCh <- fmt.Errorf("failed to read packet: %w", err)
				return
			}

			if frame != nil {
				debugLog("Packet captured: %d bytes", len(frame))

				if dnsIP, ok := extractDNSIP(frame); ok {
					debugLog("DNS response detected from IP: %v", dnsIP)
					dnsResponseCh <- dnsIP
					return
				}
			} else {
				// Small delay to prevent busy waiting when no packets
				time.Sleep(1 * time.Millisecond)
			}
		}
	}()

	// Steps 6-9: Perform 4 DNS lookups
	for i := 1; i <= 4; i++ {
		debugLog("Performing DNS lookup for domain: %v (Attempt %d)", domainFlag, i)
		if progressBar != nil {
			progressBar.Advance()
		}
		_, err := net.LookupHost(domainFlag)
		if err != nil {
			log.Printf("DNS lookup failed: %v", err)
			debugLog("DNS lookup failed: %v", err)
			if progressBar != nil {
				progressBar.Advance()
			}
			os.Exit(2)
		}
	}

	// Step 10: Start waiting for DNS response or timeout
	// Start progress bar incrementing every second
	waitDone := make(chan struct{})
	if progressBar != nil {
		go progressBar.IncrementDuringWait(captureTimeout, waitDone)
	}

	// Wait for DNS response or timeout
	select {
	case dnsIP := <-dnsResponseCh:
		// DNS response received
		close(waitDone) // Stop the progress bar incrementing
		// Ensure that the progress bar has reached totalProgress
		if progressBar != nil {
			for progressBar.current < progressBar.total {
				progressBar.Advance()
			}
		}
		if ipOnlyFlag {
			fmt.Println(dnsIP)
			debugLog("Printed DNS IP and exiting with code 0.")
		} else {
			fmt.Printf("DNS server IP: %s\n", dnsIP)
		}
		os.Exit(0)
	case err := <-errorCh:
		// Error during packet processing
		close(waitDone) // Stop the progress bar incrementing
		// Ensure that the progress bar has reached totalProgress
		if progressBar != nil {
			for progressBar.current < progressBar.total {
				progressBar.Advance()
			}
		}
		if ipOnlyFlag {
			fmt.Fprintf(os.Stderr, "Failed to capture DNS response: %v\n", err)
			debugLog("DNS response not captured; reason: %v. Exiting with code 2.", err)
		} else {
			fmt.Fprintf(os.Stderr, "Failed to capture DNS response: %v\n", err)
		}
		os.Exit(2)
	case <-time.After(captureTimeout):
		// Timeout occurred
		close(waitDone) // Stop the progress bar incrementing
		// Ensure that the progress bar has reached totalProgress
		if progressBar != nil {
			for progressBar.current < progressBar.total {
				progressBar.Advance()
			}
		}
		if ipOnlyFlag {
			fmt.Fprintf(os.Stderr, "Failed to capture DNS response: timeout after %v\n", captureTimeout)
			debugLog("DNS response capture timed out after %v. Exiting with code 2.", captureTimeout)
		} else {
			fmt.Fprintf(os.Stderr, "Failed to capture DNS response: timeout after %v\n", captureTimeout)
		}
		os.Exit(2)
	}
}

// isRoot checks if the current user is root
func isRoot() bool {
	debugLog("Checking if the current user is root.")
	currentUser, err := user.Current()
	if err != nil {
		log.Fatalf("Failed to get current user: %v", err)
	}
	debugLog("Current user UID: %s", currentUser.Uid)
	return currentUser.Uid == "0"
}

// getDefaultNetworkInterface retrieves the default network interface
func getDefaultNetworkInterface(printOutput bool, progressBar *ProgressBar) *net.Interface {
	debugLog("Fetching the default network interface.")
	iface, err := findDefaultNetworkInterface()
	if err != nil {
		if printOutput {
			fmt.Fprintf(os.Stderr, "Failed to get the default interface: %v\n", err)
		}
		debugLog("Error finding default network interface: %v", err)
		if progressBar != nil {
			progressBar.Advance()
		}
		os.Exit(1)
	}
	if progressBar != nil {
		progressBar.Advance()
	}
	return iface
}

// findDefaultNetworkInterface lists interfaces and returns the first one with a global unicast IP
func findDefaultNetworkInterface() (*net.Interface, error) {
	debugLog("Listing all network interfaces.")
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("could not list interfaces: %w", err)
	}

	for _, iface := range interfaces {
		debugLog("Checking interface: %v", iface.Name)
		addrs, err := iface.Addrs()
		if err != nil {
			debugLog("Could not get addresses for interface %v: %v", iface.Name, err)
			return nil, fmt.Errorf("could not get addresses for interface %v: %w", iface.Name, err)
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			debugLog("Found IP address: %v on interface: %v", ip, iface.Name)

			if ip.IsGlobalUnicast() {
				debugLog("Global unicast IP found: %v on interface: %v", ip, iface.Name)
				return &iface, nil
			}
		}
	}

	debugLog("No suitable default interface found.")
	return nil, fmt.Errorf("no suitable default interface found")
}

// debugLog prints debug messages if debug mode is enabled
func debugLog(format string, a ...interface{}) {
	if debug {
		log.Printf("[DEBUG] "+format, a...)
	}
}

// openAFPacketSocket creates a raw AF_PACKET socket for packet capture
func openAFPacketSocket(iface *net.Interface) (int, error) {
	// Create raw socket to capture all Ethernet frames
	fd, err := syscall.Socket(afPacket, sockRaw, int(htons(ethPAll)))
	if err != nil {
		return -1, fmt.Errorf("failed to create AF_PACKET socket: %w", err)
	}

	// Bind to interface
	sa := &sockaddrLl{
		sllFamily:   afPacket,
		sllProtocol: htons(ethPAll),
		sllIfindex:  int32(iface.Index),
	}

	_, _, errno := syscall.Syscall(syscall.SYS_BIND, uintptr(fd), uintptr(unsafe.Pointer(sa)), unsafe.Sizeof(*sa))
	if errno != 0 {
		syscall.Close(fd)
		return -1, fmt.Errorf("failed to bind socket to interface: %w", errno)
	}

	// Set socket to non-blocking mode
	if err := syscall.SetNonblock(fd, true); err != nil {
		syscall.Close(fd)
		return -1, fmt.Errorf("failed to set socket to non-blocking mode: %w", err)
	}

	debugLog("AF_PACKET socket created and bound to interface %s (index %d)", iface.Name, iface.Index)
	return fd, nil
}

// htons converts host byte order to network byte order (big endian)
func htons(x uint16) uint16 {
	return (x<<8)&0xff00 | x>>8
}

// readPacket reads a single packet from the AF_PACKET socket
func readPacket(fd int) ([]byte, error) {
	const maxFrameSize = 65536 // Maximum Ethernet frame size
	buf := make([]byte, maxFrameSize)

	n, _, err := syscall.Recvfrom(fd, buf, 0)
	if err != nil {
		if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
			// No data available, try again
			return nil, nil
		}
		debugLog("Recvfrom error: %v", err)
		return nil, err
	}

	if n == 0 {
		// Empty packet, skip
		debugLog("Received empty packet (n=0)")
		return nil, nil
	}

	debugLog("Received packet with %d bytes", n)
	return buf[:n], nil
}

// parseEthernetFrame parses basic Ethernet frame to extract IP packet
func parseEthernetFrame(frame []byte) ([]byte, bool) {
	if len(frame) < ethHeaderLen {
		return nil, false
	}

	// Check if it's IPv4 (EtherType 0x0800)
	etherType := uint16(frame[12])<<8 | uint16(frame[13])
	if etherType != ethPIPv4 {
		return nil, false
	}

	return frame[ethHeaderLen:], true
}

// parseIPPacket extracts UDP packet from IP packet
func parseIPPacket(ipPacket []byte) ([]byte, bool) {
	if len(ipPacket) < ipHeaderMin {
		return nil, false
	}

	// Check if it's UDP
	if ipPacket[9] != ipProtoUDP {
		return nil, false
	}

	// Get header length (first 4 bits * 4)
	headerLen := int(ipPacket[0]&0x0F) * 4
	if len(ipPacket) < headerLen+udpHeaderLen {
		return nil, false
	}

	return ipPacket[headerLen:], true
}

// parseUDPPacket extracts DNS data from UDP packet
func parseUDPPacket(udpPacket []byte) ([]byte, uint16, bool) {
	if len(udpPacket) < udpHeaderLen {
		return nil, 0, false
	}

	srcPort := uint16(udpPacket[0])<<8 | uint16(udpPacket[1])
	dstPort := uint16(udpPacket[2])<<8 | uint16(udpPacket[3])

	// Check if source port is DNS
	if srcPort != dnsPort {
		return nil, 0, false
	}

	// Get UDP data length
	dataLen := uint16(udpPacket[4])<<8 | uint16(udpPacket[5])
	if dataLen < udpHeaderLen || len(udpPacket) < int(dataLen) {
		return nil, 0, false
	}

	return udpPacket[udpHeaderLen:dataLen], dstPort, true
}

// extractDNSIP extracts the DNS server IP from the Ethernet frame
func extractDNSIP(frame []byte) (string, bool) {
	// Parse Ethernet frame
	ipPacket, ok := parseEthernetFrame(frame)
	if !ok {
		return "", false
	}

	// Parse IP packet
	udpPacket, ok := parseIPPacket(ipPacket)
	if !ok {
		return "", false
	}

	// Parse UDP packet
	_, _, ok = parseUDPPacket(udpPacket)
	if !ok {
		return "", false
	}

	// Extract source IP from IP header
	if len(ipPacket) < ipSrcOffset+4 {
		return "", false
	}

	srcIP := net.IP(ipPacket[ipSrcOffset : ipSrcOffset+4])
	return srcIP.String(), true
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
