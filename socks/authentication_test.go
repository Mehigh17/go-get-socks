package socks

import (
	"bufio"
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type mockCon struct {
	writtenBytes [][]byte
}

func (mockrw *mockCon) Write(p []byte) (n int, err error) {
	mockrw.writtenBytes = append(mockrw.writtenBytes, p)
	return len(p), nil
}
func (mockrw mockCon) Read(b []byte) (n int, err error)   { return len(b), nil }
func (mockrw mockCon) Close() error                       { return nil }
func (mockrw mockCon) LocalAddr() net.Addr                { return nil }
func (mockrw mockCon) RemoteAddr() net.Addr               { return nil }
func (mockrw mockCon) SetDeadline(t time.Time) error      { return nil }
func (mockrw mockCon) SetReadDeadline(t time.Time) error  { return nil }
func (mockrw mockCon) SetWriteDeadline(t time.Time) error { return nil }

var UserNameCorrectRequestFlags = []byte{
	0x01,                   // version
	0x04,                   // user len
	0x75, 0x73, 0x65, 0x72, // user string is "user"
	0x04,                   // pass len
	0x70, 0x61, 0x73, 0x73, // pass string is "pass"
}

func TestHandleBasicAuthWithSuccessfulAuthentication(t *testing.T) {
	reader := bytes.NewReader(UserNameCorrectRequestFlags)

	client := NewClient()

	mockConn := mockCon{
		writtenBytes: make([][]byte, 0),
	}
	conn := Conn{
		reader:     bufio.NewReader(reader),
		clientConn: &mockConn,
	}

	authenticatorCallCount := 0
	client.SetBasicAuth(func(userGot, passGot string) error {
		assert.Equal(t, "user", userGot)
		assert.Equal(t, "pass", passGot)

		authenticatorCallCount++
		return nil
	})

	errGot := client.handleBasicAuth(conn)

	assert.EqualValues(t, mockConn.writtenBytes[0], []byte{SubnegociationVersion, AuthenticationSuccess})
	assert.Equal(t, len(mockConn.writtenBytes), 1) // Verify that only one array of bytes has been written

	assert.Equal(t, authenticatorCallCount, 1) // Verify if the authenticator has been called once
	assert.Nil(t, errGot)
}
