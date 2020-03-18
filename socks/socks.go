package socks

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

const (
	ErrUnsupportedVersion      = "socks: unsupported version"
	ErrUnsupportedCommand      = "socks: invalid command"
	ErrAddressTypeNotSupported = "socks: address type not supported"
)

// AddrType represents the address type used in the SOCKS request/reply exchange.
type AddrType byte

const (
	IPv4Addr       AddrType = 0x01
	DomainNameAddr AddrType = 0x03
	IPv6Addr       AddrType = 0x04
)

type Addr interface {
	Type() AddrType
	Network() string
	Address() string
	Bytes() []byte
}

// FQDN represents a Fully Qualified Domain Name address type.
type FQDN string

func (fqdn FQDN) Type() AddrType  { return DomainNameAddr }
func (fqdn FQDN) Network() string { return "tcp" }
func (fqdn FQDN) Address() string { return string(fqdn) }
func (fqdn FQDN) Bytes() []byte {
	bytes := make([]byte, len(fqdn)+1)
	bytes[0] = byte(len(fqdn))
	copy(bytes[1:], []byte(string(fqdn)))
	return bytes
}

// IPv4 represents an IP address in IP version 4 format.
type IPv4 net.IP

func (ipv4 IPv4) Type() AddrType  { return IPv4Addr }
func (ipv4 IPv4) Network() string { return "tcp4" }
func (ipv4 IPv4) Address() string { return net.IP(ipv4).String() }
func (ipv4 IPv4) Bytes() []byte   { return ipv4[0:4] }

// Command is the request/reply command type.
type Command byte

const (
	Connect      Command = 0x01
	Bind         Command = 0x02
	UDPAssociate Command = 0x03
)

// ResponseType represents the type of the response for a SOCKS Reply.
type ResponseType byte

const (
	Succedeed                     = 0x00
	GeneralSOCKSServerFailure     = 0x01
	ConnectionNotAllowedByRuleset = 0x02
	NetworkUnreachable            = 0x03
	HostUnreachable               = 0x04
	ConnectionRefused             = 0x05
	TTLExpired                    = 0x06
	CommandNotSupported           = 0x07
	AddressTypeNotSupported       = 0x08
)

// AuthMethod is authentication method type described by SOCKS.
type AuthMethod byte

const (
	NoAuthentication AuthMethod = 0x00
	GSSAPI           AuthMethod = 0x01
	UsernamePassword AuthMethod = 0x02
)

// Request represents the request made by the SOCKS client to the proxy server.
type Request struct {
	Version            byte
	Command            Command
	Reserved           byte
	AddressType        AddrType
	DestinationAddress Addr
	DestinationPort    uint16
}

// Reply represents the reply sent by the proxy server to the client.
type Reply struct {
	Version     byte
	Response    ResponseType
	Reserved    byte
	AddressType AddrType
	BindAddress Addr
	BindPort    uint16
}

const (
	// SocksVersion represents the 5th version of the SOCKS RFC.
	SocksVersion uint8 = 0x05
)

// Conn represents a SOCKS connection.
type Conn struct {
	reader     *bufio.Reader
	clientConn net.Conn
}

// NewSocksConn creates a new Socks Connection
func NewSocksConn(conn net.Conn) (sockconn Conn) {
	sockconn.clientConn = conn
	sockconn.reader = bufio.NewReader(conn)
	return
}

func (conn Conn) checkVersion() error {
	ver, err := conn.reader.ReadByte()
	if err != nil {
		return err
	}

	if ver != SocksVersion {
		conn.clientConn.Close()
		return errors.New(ErrUnsupportedVersion)
	}

	return nil
}

// GetMethods obtains the methods from the SOCKS client.
func (conn Conn) GetMethods() ([]AuthMethod, error) {
	conn.checkVersion()

	methodCount, err := conn.reader.ReadByte()
	if err != nil {
		return []AuthMethod{}, err
	}

	methodsbyte := make([]byte, methodCount)
	readMethodCount, err := io.ReadFull(conn.reader, methodsbyte)
	if err != nil {
		return []AuthMethod{}, err
	}

	if int(methodCount) != readMethodCount {
		return []AuthMethod{}, errors.New(fmt.Sprintln("the number of read methods", readMethodCount, "and the expected", methodCount, " don't match"))
	}

	methods := make([]AuthMethod, methodCount)
	for i, m := range methodsbyte {
		methods[i] = AuthMethod(m)
	}

	return methods, nil
}

// ReadRequest reads the request from the active connection.
func (conn Conn) ReadRequest() (Request, error) {
	if err := conn.checkVersion(); err != nil {
		return Request{}, err
	}

	cmdByte, err := conn.reader.ReadByte()
	if err != nil {
		return Request{}, err
	}

	cmd := Command(cmdByte)
	if cmd != Connect {
		conn.WriteReply(Reply{
			Version:  SocksVersion,
			Response: CommandNotSupported,
		})
		conn.clientConn.Close()
		return Request{}, errors.New(ErrUnsupportedCommand)
	}

	// jump over reserved
	conn.reader.ReadByte()
	// ------------------

	// Read Address
	addrByte, err := conn.reader.ReadByte()
	if err != nil {
		return Request{}, err
	}

	addr := AddrType(addrByte)
	if addr != IPv4Addr && addr != IPv6Addr && addr != DomainNameAddr {
		conn.WriteReply(Reply{
			Version:  SocksVersion,
			Reserved: AddressTypeNotSupported,
		})
		conn.clientConn.Close()
		return Request{}, errors.New(fmt.Sprintln(ErrAddressTypeNotSupported, addr))
	}

	var dstAddr Addr
	var dstAddrBytes []byte
	if addr == IPv4Addr {
		dstAddrBytes = make([]byte, 4)
	} else if addr == DomainNameAddr {
		len, err := conn.reader.ReadByte()
		dstAddrBytes = make([]byte, len)

		if err != nil {
			return Request{}, err
		}
	} else if addr == IPv6Addr {
		dstAddrBytes = make([]byte, 16)
	}

	_, err = io.ReadFull(conn.reader, dstAddrBytes)
	if err != nil {
		return Request{}, err
	}

	if addr == IPv4Addr {
		dstAddr = IPv4(dstAddrBytes)
	} else if addr == DomainNameAddr {
		dstAddr = FQDN(dstAddrBytes)
	}

	// Read Port
	portBytes := make([]byte, 2)
	if _, err = io.ReadFull(conn.reader, portBytes); err != nil {
		return Request{}, err
	}
	port := binary.BigEndian.Uint16(portBytes)

	return Request{
		Version:            SocksVersion,
		Command:            cmd,
		Reserved:           0x00,
		AddressType:        addr,
		DestinationAddress: dstAddr,
		DestinationPort:    port,
	}, nil
}

// WriteReply writes a reply to an active connection.
func (conn Conn) WriteReply(reply Reply) error {
	bytes := reply.ToBytes()
	_, err := conn.clientConn.Write(bytes)

	return err
}

// ToBytes transforms the Reply into a byte array.
func (reply Reply) ToBytes() []byte {
	addrBytes := reply.BindAddress.Bytes()
	len := 6 + len(addrBytes)
	bytes := make([]byte, len)

	bytes[0] = reply.Version
	bytes[1] = byte(reply.Response)
	bytes[2] = reply.Reserved
	bytes[3] = byte(reply.AddressType)
	copy(bytes[4:len-2], addrBytes)
	binary.BigEndian.PutUint16(bytes[len-2:], reply.BindPort)

	return bytes
}
