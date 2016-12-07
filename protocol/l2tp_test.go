package protocol

import (
	"net"
	"testing"
)

func TestSCCRQ(t *testing.T) {
	wbuff := SCCRQ("InsZVA-PC", "Microsoft", 3, 8)
	laddr, err := net.ResolveUDPAddr("udp4", "222.205.47.118:1701")
	if err != nil {
		t.Error(err)
	}
	raddr, err := net.ResolveUDPAddr("udp4", "10.5.1.9:1701")
	if err != nil {
		t.Error(err)
	}
	conn, err := net.DialUDP("udp4", laddr, raddr)
	if err != nil {
		t.Error(err)
	}
	conn.Write(wbuff)
	rbuff := make([]byte, 1024)
	conn.ReadFromUDP(rbuff)
	t.Log(rbuff)
	conn.Close()
}
