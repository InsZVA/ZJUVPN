package network

import (
	"io/ioutil"
	"log"
	"net"
	"time"

	"os/exec"
	"sync"

	"encoding/hex"

	"github.com/inszva/gol2tp/protocol"
	"github.com/inszva/gol2tp/tun-go"
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
	time.Sleep(time.Second)
	err = ifce.SetInterface(net.IP(ppp.IP).String(), "255.255.255.255", "0.0.0.0", net.IP(ppp.PDNS).String())
	if err != nil {
		log.Panic(err)
	}

	log.Println("虚拟网卡准备就绪：" + hex.EncodeToString(ppp.IP))
	cmd := exec.Command("route", "add", "0.0.0.0", "MASK", "0.0.0.0", "0.0.0.0", "IF", "7", "-p")
	err = cmd.Run()
	if err != nil {
		log.Println(err)
	}
	outp, err := cmd.StdoutPipe()
	if err != nil {
		outp, err = cmd.StderrPipe()
	}
	if err == nil {
		out, _ := ioutil.ReadAll(outp)
		log.Println(string(out))
	}

	wp := sync.WaitGroup{}
	wp.Add(1)
	go func() {
		ppp.ListenAndServe(HandlerVPN)
		wp.Done()
	}()

	wp.Add(1)
	go func() {
	LOOP0:
		for {
			select {
			case <-exit:
				break LOOP0
			default:
			}
			packet := <-rbuff
			//log.Println("Read:", packet)
			n, err := ppp.SendIP(packet)
			if err != nil {
				log.Println(n, err)
			}
		}
		wp.Done()
	}()

	go ifce.Write(wbuff)

	err = ifce.Read(rbuff) // IP Packet
	if err != nil {
		log.Fatal(err)
	}

	ppp.StopListen()
	wp.Wait()
}

func HandlerVPN(ipdata []byte) {
	wbuff <- ipdata
	//log.Println("Write IP Packet:", ipdata)
}

func Exit() {
	exit <- true
	ifce.Close()
}
