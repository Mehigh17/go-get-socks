# Go Get Socks

GGS is a simple, uncomplete and work-in-progress implementation of the SOCKS5 RFC in Go. This implementation for now provides the most basic of the features. This is an educational project.

# Road map

- [x] Add implementation of handshake and basic packet exchange
- [ ] Add GSSAPI authentication support *(required for compliancy)*
- [X] Add Username/Password authentication support *(heavily recommended but not required for compliancy)*
- [X] Add support for all 3 address types *(IPv4, IPv6, FQDN)*
- [X] Add support for CONNECT request
- [ ] Add support for BIND request
- [ ] Add support for UDP ASSOCIATE request
- [ ] Add UDP relay server
- [ ] Add rule sets for configurable allowable hosts

# Usage

Import the package and start the server:
```go
import "github.com/Mehigh17/go-get-socks"

func main() {
    socks.Start("tcp", ":9050") // 9050 is the port the socks server will run on
}
```

Running the existing /cmd/ binary will start the server on default 8080 port unless another port is given in run arguments.

# License

MIT