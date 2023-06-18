package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {
	// Define a flag for the domain
	domainPtr := flag.String("domain", "example.com", "the domain for DNS lookup")
	flag.Parse()

	// Identify the default interface
	fmt.Println()
	iface, err := getDefaultInterface()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}
	fmt.Printf("Default interface: %v\n", iface.Name)

	// Initialize packet capture
	handle, err := pcap.OpenLive(iface.Name, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Set filter to only capture DNS packets
	err = handle.SetBPFFilter("port 53")
	if err != nil {
		log.Fatal(err)
	}

	// Create a wait group to wait for DNS reply
	var wg sync.WaitGroup
	wg.Add(1)

	// Start packet capture in a separate goroutine
	go func() {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			if packet.NetworkLayer() != nil && packet.TransportLayer() != nil {
				srcIP := packet.NetworkLayer().NetworkFlow().Src()
				srcPort := packet.TransportLayer().TransportFlow().Src()

				// Check if this is a DNS response packet
				if srcPort.String() == "53" {
					log.Printf("DNS response from: %s\n", srcIP)
					wg.Done() // Signal that DNS reply is captured
					return    // Exit the goroutine after capturing DNS reply
				}
			}
		}
	}()

	// Perform DNS request
	log.Printf("Making DNS requests")
	for i := 0; i < 4; i++ {
		_, err = net.LookupHost(*domainPtr)
		if err != nil {
			log.Fatal(err)
		}
	}
	log.Println("DNS request made.")

	// Wait for DNS reply to be captured before exiting
	wg.Wait()
}

func getDefaultInterface() (*net.Interface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
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

	return nil, fmt.Errorf("no default interface found")
}
