package socks

import (
	"io"
	"log"
	"net"
	"strconv"
)

// Start starts the SOCKS 5 server on the given address.
//
// Network can be "tcp" or "udp"
func Start(network, address string) (net.Listener, error) {
	ln, err := net.Listen(network, address)
	if err != nil {
		panic(err)
	}

	log.Println("SOCKS5 server listening on", address)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}

		sockConn := NewSocksConn(conn)
		go handleConnection(sockConn)
	}
}

func handleConnection(conn Conn) {
	methods, err := conn.GetMethods()
	if err != nil {
		log.Println(err)
		return
	}

	if !hasMethod(NoAuthentication, methods) {
		log.Println("SOCKS client doesn't support 'no authentication' method.")
		conn.clientConn.Close()
		return
	}

	conn.clientConn.Write([]byte{SocksVersion, byte(NoAuthentication)})

	req, err := conn.ReadRequest()
	if err != nil {
		log.Println(err)
		conn.clientConn.Close()
		return
	}

	// create TCP connection with target
	addr := net.JoinHostPort(req.DestinationAddress.Address(), strconv.Itoa(int(req.DestinationPort)))
	targetConn, err := net.Dial(req.DestinationAddress.Network(), addr)
	if err != nil {
		conn.clientConn.Close()
		log.Println(err)
		return
	}
	defer targetConn.Close()

	err = conn.WriteReply(Reply{
		Version:     req.Version,
		Response:    Succedeed,
		Reserved:    0x00,
		AddressType: req.AddressType,
		BindAddress: req.DestinationAddress, // TODO: Put the actual target connection address.
		BindPort:    req.DestinationPort,    // Idem as above.
	})
	if err != nil {
		log.Println(err)
		return
	}

	go io.Copy(conn.clientConn, targetConn)
	io.Copy(targetConn, conn.clientConn)
}

func hasMethod(method AuthMethod, methods []AuthMethod) bool {
	for _, m := range methods {
		if m == method {
			return true
		}
	}

	return false
}
