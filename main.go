package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/user"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const appversion = "1.0.3"
const captureTimeout = 10 * time.Second

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

func main() {
	// Parse command-line arguments
	domain, printVersion, ipOnly, debugFlag := parseArguments()
	debug = *debugFlag

	debugLog("Parsed arguments: domain=%s, printVersion=%v, ipOnly=%v, debug=%v", *domain, *printVersion, *ipOnly, *debugFlag)

	// Suppress log output if ipOnly is set
	if *ipOnly {
		log.SetOutput(os.Stderr)
		log.SetFlags(0)
		debugLog("ipOnly flag is set; logging output suppressed.")
	}

	// Print version and exit if requested
	if *printVersion {
		fmt.Printf("Version: %s\n", appversion)
		debugLog("Printed version and exiting.")
		os.Exit(0)
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
		if !*ipOnly {
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
	iface := getDefaultNetworkInterface(!*ipOnly, progressBar)
	if !*ipOnly && !debug {
		fmt.Printf("Default interface: %v\n", iface.Name)
	}
	debugLog("Default network interface obtained: %v", iface.Name)

	// Step 3: Open live packet capture
	if progressBar != nil {
		progressBar.Advance()
	}
	handle, err := pcap.OpenLive(iface.Name, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Printf("Failed to open interface for packet capture: %v", err)
		debugLog("Failed to open packet capture: %v", err)
		if progressBar != nil {
			progressBar.Advance()
		}
		os.Exit(1)
	}
	defer func() {
		handle.Close()
		debugLog("Packet capture handle closed.")
		if progressBar != nil {
			progressBar.Advance()
		}
	}()

	// Step 4: Set BPF filter
	if progressBar != nil {
		progressBar.Advance()
	}
	debugLog("Setting BPF filter to 'port 53' for DNS packets.")
	if err := handle.SetBPFFilter("port 53"); err != nil {
		log.Printf("Failed to set BPF filter: %v", err)
		debugLog("Failed to set BPF filter: %v", err)
		if progressBar != nil {
			progressBar.Advance()
		}
		handle.Close()
		os.Exit(1)
	}

	// Step 5: Start packet processing
	if progressBar != nil {
		progressBar.Advance()
	}
	dnsResponseCh := make(chan string)
	errorCh := make(chan error)

	go func() {
		debugLog("Starting packet processing goroutine.")
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			debugLog("Packet captured: %v", packet)
			if packet.NetworkLayer() != nil && packet.TransportLayer() != nil {
				srcPort := packet.TransportLayer().TransportFlow().Src().String()
				if srcPort == "53" {
					dnsIP := packet.NetworkLayer().NetworkFlow().Src().String()
					debugLog("DNS response detected from IP: %v", dnsIP)
					dnsResponseCh <- dnsIP
					return
				}
			}
		}
		// If the packetSource channel is closed without receiving a DNS response
		errorCh <- fmt.Errorf("packet source closed without capturing DNS response")
		debugLog("Packet processing goroutine ended without capturing DNS response.")
	}()

	// Steps 6-9: Perform 4 DNS lookups
	for i := 1; i <= 4; i++ {
		debugLog("Performing DNS lookup for domain: %v (Attempt %d)", *domain, i)
		if progressBar != nil {
			progressBar.Advance()
		}
		_, err := net.LookupHost(*domain)
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
		for progressBar.current < progressBar.total {
			progressBar.Advance()
		}
		if *ipOnly {
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
		for progressBar.current < progressBar.total {
			progressBar.Advance()
		}
		if *ipOnly {
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
		for progressBar.current < progressBar.total {
			progressBar.Advance()
		}
		if *ipOnly {
			fmt.Fprintf(os.Stderr, "Failed to capture DNS response: timeout after %v\n", captureTimeout)
			debugLog("DNS response capture timed out after %v. Exiting with code 2.", captureTimeout)
		} else {
			fmt.Fprintf(os.Stderr, "Failed to capture DNS response: timeout after %v\n", captureTimeout)
		}
		os.Exit(2)
	}
}

// parseArguments parses command-line arguments
func parseArguments() (*string, *bool, *bool, *bool) {
	domain := flag.String("domain", "example.com", "the domain for DNS lookup")
	printVersion := flag.Bool("version", false, "print version and exit")
	ipOnly := flag.Bool("iponly", false, "print only the IP address of the DNS server")
	debugFlag := flag.Bool("debug", false, "enable debug output")
	flag.Parse()
	return domain, printVersion, ipOnly, debugFlag
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

// captureDNSResponse handles DNS response capturing
func captureDNSResponse(iface *net.Interface, domain string, progressBar *ProgressBar) (bool, string, error) {
	// This function is now redundant as packet capturing is handled in main
	// Keeping it for potential future use or refactoring
	return true, "", nil
}
