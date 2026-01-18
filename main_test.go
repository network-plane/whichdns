package main

import (
	"testing"
)

func TestFlags(t *testing.T) {
	// Test default values
	if domainFlag != "example.com" {
		t.Errorf("Expected default domain 'example.com', got '%s'", domainFlag)
	}
	if ipOnlyFlag != false {
		t.Errorf("Expected default ipOnly false, got %v", ipOnlyFlag)
	}
	if debugFlag != false {
		t.Errorf("Expected default debug false, got %v", debugFlag)
	}

	// Test setting flags
	domainFlag = "test.com"
	ipOnlyFlag = true
	debugFlag = true

	if domainFlag != "test.com" {
		t.Errorf("Expected domain 'test.com', got '%s'", domainFlag)
	}
	if !ipOnlyFlag {
		t.Errorf("Expected ipOnly to be true")
	}
	if !debugFlag {
		t.Errorf("Expected debug to be true")
	}
}

func TestFindDefaultNetworkInterface(t *testing.T) {
	iface, err := findDefaultNetworkInterface()
	if err != nil {
		t.Fatalf("Error finding default network interface: %v", err)
	}
	if iface == nil {
		t.Fatal("Expected a valid network interface, got nil")
	}
	// Check that the interface has a valid name
	if iface.Name == "" {
		t.Errorf("Expected a valid interface name, got an empty string")
	}
}

func TestGetDefaultNetworkInterface(t *testing.T) {
	iface := getDefaultNetworkInterface(true, nil)
	if iface == nil {
		t.Fatalf("Expected a network interface, got nil")
	}
	// Check that the interface has a valid name
	if iface.Name == "" {
		t.Errorf("Expected a valid interface name, got an empty string")
	}
}

// To test isRoot, you should run the test manually with and without root privileges.
func TestIsRootManual(t *testing.T) {
	if isRoot() {
		t.Log("Test is running as root")
	} else {
		t.Log("Test is running as a non-root user")
	}
}
