package main

import (
	"fmt"
	socks "go-get-socks/socks"
	"log"
	"os"
	"strconv"
)

const (
	DefaultPort = 8080
)

func main() {
	var port int = DefaultPort
	if len(os.Args) == 2 {
		var err error
		port, err = strconv.Atoi(os.Args[1])
		if err != nil {
			log.Println(err)
			port = DefaultPort
		}
	} else {
		log.Printf("no port specified on launch, running default %d\n", DefaultPort)
	}

	socks.Start("tcp", fmt.Sprintf(":%d", port))
}