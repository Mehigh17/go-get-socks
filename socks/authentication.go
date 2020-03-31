package socks

import (
	"errors"
	"io"
)

var (
	ErrInvalidCredentials           = errors.New("socks: invalid credentials")
	ErrInvalidSubnegociationVersion = errors.New("socks: invalid subnegociation version for username/password")
)

const (
	// NoAcceptableMethods of authentication have been found.
	NoAcceptableMethods = 0xFF
)

const (
	AuthenticationSuccess = 0x00
)

// AuthMethod is authentication method type described by SOCKS.
type AuthMethod byte

const (
	NoAuthentication AuthMethod = 0x00
	GSSAPI           AuthMethod = 0x01
	UsernamePassword AuthMethod = 0x02
)

// AuthError represents an error returned in case of failed authentication.
type AuthError struct {
	Message    string
	ResultCode byte
}

func (e AuthError) Error() string {
	return e.Message
}

// Code returns the result code of the failed authentication. (MUST NOT BE 0)
func (e AuthError) Code() byte {
	return e.ResultCode
}

// BasicAuthenticator represents a function required to authenticate a user by providing username and password, and returning AuthError in case of an authentication failure.
type BasicAuthenticator func(string, string) error

// SetNoAuthentication sets the proxy to not require any authentication upon using it.
func (client *Client) SetNoAuthentication() {
	client.authMethod = NoAuthentication
}

// SetBasicAuth sets the proxy to require an username and password upon connection.
//
// A validator function must be provided which will validate the username and password received as (username string, password string).
// The validator function must return nil error if the authentication has succeed, otherwise provide a byte representing the error code, and an error specifying why the authentication failed.
func (client *Client) SetBasicAuth(authenticator BasicAuthenticator) {
	client.authMethod = UsernamePassword
	client.authenticator = authenticator
}

func (client Client) handleBasicAuth(conn Conn) error {
	ver, err := conn.reader.ReadByte()

	if err != nil {
		return err
	}

	if ver != 0x01 {
		return ErrInvalidSubnegociationVersion
	}

	usernameLen, err := conn.reader.ReadByte()
	if err != nil {
		return err
	}

	usernameBytes := make([]byte, usernameLen)
	io.ReadFull(conn.reader, usernameBytes)

	passwordLen, err := conn.reader.ReadByte()
	if err != nil {
		return err
	}

	passwordBytes := make([]byte, passwordLen)
	io.ReadFull(conn.reader, passwordBytes)

	err = client.authenticator(string(usernameBytes), string(passwordBytes))
	if err != nil {
		authError, ok := err.(*AuthError)
		if ok {
			_, err = conn.clientConn.Write([]byte{authError.Code()})
		} else {
			_, err = conn.clientConn.Write([]byte{0x01}) // Return arbitrary byte other than 0 to signal that authentication failed.
		}
		return err
	}

	_, err = conn.clientConn.Write([]byte{AuthenticationSuccess})
	if err != nil {
		return err
	}

	return nil
}
