package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/user"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const appversion = "1.0.3"
const captureTimeout = 10 * time.Second

func main() {
	// Initialize and parse arguments
	domain, printVersion, ipOnly := parseArguments()

	// If the ipOnly flag is set, suppress log output
	if *ipOnly {
		log.SetOutput(os.Stderr)
		log.SetFlags(0)
	}

	// Print version and exit if requested
	if *printVersion {
		fmt.Printf("Version: %s\n", appversion)
		os.Exit(0)
	}

	// Check for root privileges
	if !isRoot() {
		if !*ipOnly {
			fmt.Println("This program requires root privileges to run.")
			fmt.Println("Please run it as root or with sudo.")
		}
		os.Exit(1)
	}

	// Get the default network interface
	iface := getDefaultNetworkInterface(!*ipOnly)

	// Start packet capture and DNS request
	success, dnsIP := captureDNSResponse(iface, *domain)

	// Output only the IP of the DNS server if the ipOnly flag is set
	if *ipOnly {
		if success {
			fmt.Println(dnsIP)
			os.Exit(0)
		} else {
			os.Exit(2)
		}
	}

	// Exit with the appropriate code based on whether a DNS response was captured
	if success {
		os.Exit(0)
	} else {
		os.Exit(2)
	}
}

func parseArguments() (*string, *bool, *bool) {
	domain := flag.String("domain", "example.com", "the domain for DNS lookup")
	printVersion := flag.Bool("version", false, "print version and exit")
	ipOnly := flag.Bool("iponly", false, "print only the IP address of the DNS server")
	flag.Parse()
	return domain, printVersion, ipOnly
}

// isRoot checks if the current user is root
func isRoot() bool {
	currentUser, err := user.Current()
	if err != nil {
		log.Fatalf("Failed to get current user: %v", err)
	}
	return currentUser.Uid == "0"
}

func getDefaultNetworkInterface(printOutput bool) *net.Interface {
	iface, err := findDefaultNetworkInterface()
	if err != nil {
		if printOutput {
			log.Printf("Failed to get the default interface: %v", err)
		}
		os.Exit(1)
	}
	if printOutput {
		fmt.Printf("Default interface: %v\n", iface.Name)
	}
	return iface
}

func findDefaultNetworkInterface() (*net.Interface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("could not list interfaces: %w", err)
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
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

			if ip.IsGlobalUnicast() {
				return &iface, nil
			}
		}
	}

	return nil, fmt.Errorf("no suitable default interface found")
}

func captureDNSResponse(iface *net.Interface, domain string) (bool, string) {
	handle, err := pcap.OpenLive(iface.Name, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Printf("Failed to open interface for packet capture: %v", err)
		os.Exit(1)
	}
	defer handle.Close()

	// Capture only DNS packets
	if err := handle.SetBPFFilter("port 53"); err != nil {
		log.Printf("Failed to set BPF filter: %v", err)
		os.Exit(1)
	}

	dnsResponseCh := make(chan string)
	go func() {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			if packet.NetworkLayer() != nil && packet.TransportLayer() != nil {
				if packet.TransportLayer().TransportFlow().Src().String() == "53" {
					dnsIP := packet.NetworkLayer().NetworkFlow().Src().String()
					dnsResponseCh <- dnsIP
					close(dnsResponseCh)
					return
				}
			}
		}
	}()

	// Make multiple DNS requests
	for i := 0; i < 4; i++ {
		if _, err := net.LookupHost(domain); err != nil {
			log.Printf("DNS lookup failed: %v", err)
			os.Exit(2)
		}
	}

	select {
	case dnsIP := <-dnsResponseCh:
		return true, dnsIP
	case <-time.After(captureTimeout):
		return false, ""
	}
}
