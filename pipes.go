package main

import (
	"fmt"
	"io"
	"net/rpc"
	"net/rpc/jsonrpc"
	"os"

	"github.com/nymsio/nyms-agent/protocol"
	gl "github.com/op/go-logging"
)

var logger = gl.MustGetLogger("nymsd")

type pipePair struct {
	input  io.Reader
	output io.Writer
}

func (pp pipePair) Read(p []byte) (int, error) {
	return pp.input.Read(p)
}

func (pp pipePair) Write(p []byte) (int, error) {
	return pp.output.Write(p)
}

func (pp pipePair) Close() (e error) {
	if err := tryClose(pp.input); err != nil {
		e = err
	}
	if err := tryClose(pp.output); err != nil && e == nil {
		e = err
	}

	return e
}

func tryClose(x interface{}) error {
	if c, ok := x.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

func runPipeServer(protoDebug bool) {
	protocol := new(protocol.Protocol)
	rpc.Register(protocol)
	pp, err := createPipePair(os.Stdin, os.Stdout, protoDebug)
	if err != nil {
		logger.Warning(fmt.Sprintf("Failed to create pipe pair: %s", err))
		return
	}
	codec := jsonrpc.NewServerCodec(pp)
	logger.Info("Starting...")
	rpc.ServeCodec(codec)
}

func createPipePair(r io.Reader, w io.Writer, protoDebug bool) (*pipePair, error) {
	/*
		if protoDebug {
			logger.Info("Creating debug pipes")
			reader, writer, err := logger.OpenProtocolLog(r, w)
			if err != nil {
				return nil, err
			}
			return &pipePair{reader, writer}, nil
		}
	*/
	return &pipePair{r, w}, nil
}
