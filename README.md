# whichdns
When you do a DNS request, which DNS server is used? This tool will tell you.
It does a DNS request while capturing network packets using native AF_PACKET sockets and gets the DNS server that replied.

Warning: Requires root access since it captures network packets while doing the DNS requests.


## Usage/Examples

### get DNS server
```bash
sudo ./whichdns
```

### Reutrn only the DNS server for use in scripts
```bash
sudo ./whichdns --iponly
```

## How To build
No external dependencies required - uses only native Linux AF_PACKET sockets.

### Build
```bash
go build
```

### Requirements
- Linux (AF_PACKET sockets are Linux-specific)
- Root privileges (for raw socket access)
- Go 1.19+ (for AF_PACKET support)

## Example output
```bash
Default interface: eno1
[████████████████████████████████████████] 100.00%
DNS server IP: 1.1.1.1
```

### With --iponly flag (script-friendly)
```bash
$ sudo ./whichdns --iponly
1.1.1.1
```

## Technical Implementation

This tool uses **native Linux AF_PACKET raw sockets** to capture Ethernet frames directly from the network interface. Unlike traditional packet capture libraries, it performs all packet parsing and filtering in userspace using pure Go code.

### Why AF_PACKET?
- **Zero external dependencies** - No libpcap, CGO, or system libraries required
- **Smaller binaries** - No vendored C libraries
- **Better portability** - Only requires Linux kernel support
- **Full control** - Custom packet dissection and filtering logic

### How it works:
1. Creates raw AF_PACKET socket bound to the default network interface
2. Performs DNS lookups to generate network traffic
3. Captures Ethernet frames containing DNS responses
4. Parses Ethernet → IP → UDP → DNS packets in userspace
5. Extracts the responding DNS server IP address

**Requirements:** Linux with AF_PACKET support (kernel 2.2+), root privileges for raw socket access.

## Documentation & Compliance
[![Go Mod](https://img.shields.io/github/go-mod/go-version/earentir/whichdns)]()

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/8653/badge)](https://www.bestpractices.dev/projects/8653)

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/earentir/whichdns/badge)](https://securityscorecards.dev/viewer/?uri=github.com/earentir/whichdns)


## Contributing

Contributions are always welcome!
All contributions are required to follow the https://google.github.io/styleguide/go/

## Vulnerability Reporting

Please report any security vulnerabilities to the project using issues or directly to the owner.

## Code of Conduct

 This project follows the go project code of conduct, please refer to https://go.dev/conduct for more details

## Roadmap

- [x] Add --iponly option to return just the DNS server IP for scripting
- [x] Replace libpcap with native AF_PACKET sockets
- [ ] Add support for other packet capture methods (BPF, etc.)

## Authors

- [@earentir](https://www.github.com/earentir)


## License

I will always follow the Linux Kernel License as primary, if you require any other OPEN license please let me know and I will try to accomodate it.

[![License](https://img.shields.io/github/license/earentir/gitearelease)](https://opensource.org/license/gpl-2-0)
