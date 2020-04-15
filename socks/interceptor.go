package socks

import "io"

// PacketHandle reprresents a callback function which contains the data packet, and returns a potentially altered data packet.
// If returning null bytes, the packet won't be sent.
type PacketHandle func([]byte) []byte

// Interceptor is a structure allowing to intercept packet transfer and invoke callbacks with their contents.
type Interceptor struct {
	src         io.Reader
	dst         io.Writer
	writeHandle PacketHandle
	readHandle  PacketHandle
}

// NewInterceptor creates a new instance of an Interceptor.
func NewInterceptor(dst io.Writer, src io.Reader, writeHandle PacketHandle, readHandle PacketHandle) Interceptor {
	i := Interceptor{
		src:         src,
		dst:         dst,
		writeHandle: writeHandle,
		readHandle:  readHandle,
	}

	return i
}

func (i Interceptor) Write(p []byte) (int, error) {
	if i.writeHandle != nil {
		p = i.writeHandle(p)
		if p == nil {
			return 0, nil
		}
	}

	return i.dst.Write(p)
}

func (i Interceptor) Read(p []byte) (int, error) {
	if i.readHandle != nil {
		p := i.readHandle(p)
		if p == nil {
			return 0, nil
		}
	}

	return i.src.Read(p)
}
