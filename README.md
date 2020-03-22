# Go Get Socks

GGS is a simple, uncomplete and work-in-progress implementation of the SOCKS5 RFC in Go. This implementation for now provides the most basic of the features. This is an educational project.

# Road map

- [x] Add implementation of handshake and basic packet exchange
- [ ] Add GSSAPI authentication support *(required for compliancy)*
- [ ] Add Username/Password authentication support *(heavily recommended but not required for compliancy)*
- [X] Add support for all 3 address types *(IPv4, IPv6, FQDN)*
- [X] Add support for CONNECT request
- [ ] Add support for BIND request
- [ ] Add UDP requests support
- [ ] Add rule sets for configurable allowable hosts

# License

MIT