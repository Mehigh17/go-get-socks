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
