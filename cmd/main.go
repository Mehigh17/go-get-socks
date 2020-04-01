package main

import (
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/Mehigh17/go-get-socks/socks"
)

const (
	DefaultPort = 8080
)

// Test with: ncat -C --proxy localhost:8080 --proxy-type socks5 --proxy-auth none google.com 80
func main() {
	socksClient := socks.Client{}
	socksClient.SetNoAuthentication()

	var port int = DefaultPort
	if len(os.Args) == 2 {
		var err error
		port, err = strconv.Atoi(os.Args[1])
		if err != nil {
			log.Println(err)
			port = DefaultPort
		}
	} else if len(os.Args) == 4 {
		log.Print("Server started with user/pass authentication required.")

		socksClient.SetBasicAuth(func(username, password string) error {
			if username == os.Args[2] && password == os.Args[3] {
				return nil
			}

			return socks.AuthError{
				Message:    "Invalid username or password",
				ResultCode: 0x01,
			}
		})
	} else {
		log.Printf("command [port [username password]] (default port %d)\n", DefaultPort)
	}

	socksClient.Start("tcp", fmt.Sprintf(":%d", port))
}
