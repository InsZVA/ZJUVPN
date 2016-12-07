package main

import (
	"flag"
	"math/rand"
	"os"
	"os/signal"
	"sync"

	"github.com/inszva/gol2tp/network"
	"github.com/inszva/gol2tp/protocol"
)

func main() {
	localAddr := flag.String("l", "222.205.47.118", "本机有线网卡的ip地址")
	lnsAddr := flag.String("r", "10.5.1.9", "LNS服务器地址")
	username := flag.String("u", "", "用户名，例如3140104024@c，@c表示30元，@a表示10元，@d表示50元")
	password := flag.String("p", "", "密码")
	flag.Parse()
	session := protocol.L2TPSession{
		RAddr:          *lnsAddr,
		LAddr:          *localAddr,
		LTunnelId:      17,
		LReceiveWindow: 8,
		LSessionId:     10,
	}
	session.CreateConn()
	session.CreateTunnel()
	session.CreateSession()
	ppp := protocol.PPPSession{
		L2tpSession:  &session,
		LMagicNumber: rand.Uint32(),
		Username:     *username,
		Password:     *password,
	}
	ppp.LCPContact()
	ppp.CHAPContact()
	ppp.IPCPContact()

	wp := sync.WaitGroup{}
	// VPN Transfrom
	wp.Add(1)
	go func() {
		network.NewCard(&ppp)
		wp.Done()
	}()

	// Clean
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, os.Kill)
	<-c
	network.Exit()
	wp.Wait()

	ppp.Terminate()
	session.CDN()
	session.StopCCN()
}
