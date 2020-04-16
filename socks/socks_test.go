package socks

import (
	"bufio"
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReplyToBytes(t *testing.T) {
	reply := Reply{
		Version:     0x05,
		Response:    0x01,
		Reserved:    0x00,
		AddressType: 0x05,
		BindAddress: FQDN("test"),
		BindPort:    0x1234,
	}

	expected := []byte{
		0x05, 0x01, 0x00, 0x05,
		0x04,                   // fqdn len
		0x74, 0x65, 0x73, 0x74, // addr
		0x12, 0x34,
	}

	got := reply.ToBytes()

	assert.EqualValues(t, expected, got)
}

func Test_CheckVersion_With_ValidVersion(t *testing.T) {
	reader := bytes.NewReader([]byte{SocksVersion})

	conn := Conn{
		reader:     bufio.NewReader(reader),
		clientConn: nil,
	}

	errGot := conn.checkVersion()
	assert.Nil(t, errGot)
}

func Test_CheckVersion_With_InvalidVersion(t *testing.T) {
	const invalidVersion = 0x00
	reader := bytes.NewReader([]byte{invalidVersion})

	conn := Conn{
		reader:     bufio.NewReader(reader),
		clientConn: nil,
	}

	errGot := conn.checkVersion()
	assert.True(t, errors.Is(ErrUnsupportedVersion, errGot))
}

func Test_GetMethods_With_ValidMethods(t *testing.T) {
	reader := bytes.NewReader([]byte{
		SocksVersion,
		0x03,                                                         // method count
		byte(NoAuthentication), byte(UsernamePassword), byte(GSSAPI), // methods
	})

	conn := Conn{
		reader:     bufio.NewReader(reader),
		clientConn: nil,
	}

	methodsGot, err := conn.GetMethods()
	assert.EqualValues(t, methodsGot, []AuthMethod{NoAuthentication, UsernamePassword, GSSAPI})
	assert.Nil(t, err)
}

var addresstests = []struct {
	addrType AddrType
	bytes    []byte
}{
	{IPv4Addr, []byte{1, 2, 3, 4}},
	{IPv6Addr, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}},
}

func Test_ReadAddress_Given_ValidIpVX(t *testing.T) {
	for _, table := range addresstests {
		readerBytes := []byte{byte(table.addrType)}
		readerBytes = append(readerBytes, table.bytes...)

		reader := bytes.NewReader(readerBytes)

		conn := Conn{
			reader:     bufio.NewReader(reader),
			clientConn: nil,
		}

		addr, err := conn.readAddress()
		assert.Equal(t, addr.Type(), table.addrType)
		assert.EqualValues(t, addr.Bytes(), table.bytes)
		assert.Nil(t, err)
	}
}

func Test_ReadAddress_Given_ValidFQDN(t *testing.T) {
	fqdnBytes := []byte{
		5,
		1, 2, 3, 4, 5,
	}

	readerBytes := []byte{byte(DomainNameAddr)}
	readerBytes = append(readerBytes, fqdnBytes...)

	reader := bytes.NewReader(readerBytes)

	conn := Conn{
		reader:     bufio.NewReader(reader),
		clientConn: nil,
	}

	addr, err := conn.readAddress()
	assert.Equal(t, addr.Type(), DomainNameAddr)
	assert.EqualValues(t, addr.Bytes(), fqdnBytes)
	assert.Nil(t, err)
}
