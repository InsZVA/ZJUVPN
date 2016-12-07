package network

import (
	"log"

	"sync"

	"github.com/inszva/gol2tp/protocol"
	"github.com/songgao/water"
)

var ifce *water.Interface

var exit = make(chan bool, 1)

func NewCard(ppp *protocol.PPPSession) {
	ifce, err := water.NewTUN("")
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("虚拟网卡名称: %s\n", ifce.Name())

	wp := sync.WaitGroup{}
	wp.Add(1)
	go func() {
		ppp.ListenAndServe(HandlerVPN)
		wp.Done()
	}()

	packet := make([]byte, 2000)
LOOP:
	for {
		select {
		case <-exit:
			break LOOP
		default:
		}
		n, err := ifce.Read(packet) // IP Packet
		if err != nil {
			log.Fatal(err)
		}
		ppp.SendIP(packet[4:n])
	}

	ppp.StopListen()
	wp.Wait()
}

func HandlerVPN(ipdata []byte) {
	ifce.Write(ipdata)
}

func Exit() {
	exit <- true
	ifce.Close()
}
