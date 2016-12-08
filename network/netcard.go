package network

import (
	"log"
	"net"

	"sync"

	"encoding/hex"

	"github.com/GameXG/tun-go"
	"github.com/inszva/gol2tp/protocol"
)

var ifce tun.Tun

var exit = make(chan bool, 1)
var rbuff = make(chan []byte, 1024)
var wbuff = make(chan []byte, 1024)

func NewCard(ppp *protocol.PPPSession) {
	var err error
	ifce, err = tun.OpenTunTap(net.IP(ppp.IP), net.IP([]byte{0, 0, 0, 0}), net.IP([]byte{0, 0, 0, 0}))
	if err != nil {
		log.Panic(err)
	}

	log.Println("虚拟网卡准备就绪：" + hex.EncodeToString(ppp.IP))

	wp := sync.WaitGroup{}
	wp.Add(1)
	go func() {
		ppp.ListenAndServe(HandlerVPN)
		wp.Done()
	}()

LOOP:
	for {
		select {
		case <-exit:
			break LOOP
		default:
		}
		err := ifce.Read(rbuff) // IP Packet
		if err != nil {
			log.Fatal(err)
		}
		packet := <-rbuff
		log.Println("Read IP Packet:", packet)
		ppp.SendIP(packet)
	}

	ppp.StopListen()
	wp.Wait()
}

func HandlerVPN(ipdata []byte) {
	wbuff <- ipdata
	ifce.Write(wbuff)
	log.Println("Write IP Packet:", ipdata)
}

func Exit() {
	exit <- true
	ifce.Close()
}
