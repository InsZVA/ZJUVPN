package protocol

import (
	"log"
	"net"
)

const (
	STATUS_SCCRQ = iota
	STATUS_SCCRP
	STATUS_SCCCN
	STATUS_ICRQ
	STATUS_ICRP
	STATUS_ICCN
	STATUS_ZLB
)

type L2TPSession struct {
	Nr             uint16
	Ns             uint16
	LTunnelId      uint16
	RTunnelId      uint16
	LSessionId     uint16
	RSessionId     uint16
	LReceiveWindow uint16
	RReceiveWindow uint16
	LAddr          string
	RAddr          string
	Conn           *net.UDPConn
	Status         int
}

func (l2tpSession *L2TPSession) CreateConn() {
	laddr, err := net.ResolveUDPAddr("udp4", l2tpSession.LAddr+":1701")
	if err != nil {
		panic(err)
	}
	raddr, err := net.ResolveUDPAddr("udp4", l2tpSession.RAddr+":1701")
	if err != nil {
		panic(err)
	}
	conn, err := net.DialUDP("udp4", laddr, raddr)
	if err != nil {
		panic(err)
	}
	l2tpSession.Conn = conn
}

func (l2tpSession *L2TPSession) CreateTunnel() {
	conn := l2tpSession.Conn

	l2tpSession.Status = STATUS_SCCRQ
	wbuff := SCCRQ("InsZVA-PC", "Microsoft", l2tpSession.LTunnelId, l2tpSession.LReceiveWindow)
	conn.Write(wbuff)
	l2tpSession.Status = STATUS_SCCRP

	rbuff := make([]byte, 1500)
	conn.ReadFromUDP(rbuff)
	sccrp, err := ReadSCCRP(rbuff)
	if err != nil {
		panic(err)
	}

	l2tpSession.Nr = sccrp.Nr
	l2tpSession.Ns = sccrp.Ns
	l2tpSession.RTunnelId = sccrp.AssignedTunnelId
	l2tpSession.RReceiveWindow = sccrp.ReceiveWindowSize

	l2tpSession.Status = STATUS_SCCCN
	l2tpSession.Ns++
	wbuff = SCCCN(l2tpSession.RTunnelId, 0, l2tpSession.Ns, l2tpSession.Nr)
	conn.Write(wbuff)

}

func (l2tpSession *L2TPSession) CreateSession() {
	conn := l2tpSession.Conn

	l2tpSession.Status = STATUS_ICRQ
	l2tpSession.Ns++
	wbuff := ICRQ(l2tpSession.RTunnelId, 0, l2tpSession.Ns, l2tpSession.Nr, l2tpSession.LSessionId, 0)
	conn.Write(wbuff)

	l2tpSession.Status = STATUS_ICRP
	rbuff := make([]byte, 1500)
	conn.ReadFromUDP(rbuff)
	icrp, err := ReadICRP(rbuff)
	if err != nil {
		panic(err)
	}
	l2tpSession.RSessionId = icrp.AssignedSessionId

	l2tpSession.Status = STATUS_ICCN
	l2tpSession.Ns++
	l2tpSession.Nr++
	wbuff = ICCN(l2tpSession.RTunnelId, l2tpSession.RSessionId, l2tpSession.Ns, l2tpSession.Nr)
	conn.Write(wbuff)

	l2tpSession.Status = STATUS_ZLB
	l2tpSession.Ns++
	wbuff = L2TPControlHEAD(l2tpSession.RTunnelId, 0, l2tpSession.Ns, l2tpSession.Nr)
	conn.Write(wbuff)
}

func (l2tpSession *L2TPSession) SendData(data []byte) (int, error) {
	dataPacket := make([]byte, 8)
	length := 8 + len(data)
	dataPacket[0] = LENGTH_EXIST
	dataPacket[1] = VERSION
	dataPacket[2] = byte(length >> 8)
	dataPacket[3] = byte(length)
	dataPacket[4] = byte(l2tpSession.RTunnelId >> 8)
	dataPacket[5] = byte(l2tpSession.RTunnelId)
	dataPacket[6] = byte(l2tpSession.RSessionId >> 8)
	dataPacket[7] = byte(l2tpSession.RSessionId)
	dataPacket = append(dataPacket, data...)

	return l2tpSession.Conn.Write(dataPacket)
}

func (l2tpSession *L2TPSession) CDN() {
	conn := l2tpSession.Conn
	l2tpSession.Ns++
	wbuff := CDN(l2tpSession.RTunnelId, l2tpSession.RSessionId, l2tpSession.Ns, l2tpSession.Nr, l2tpSession.LSessionId)
	conn.Write(wbuff)
	l2tpSession.LSessionId = 0
	log.Println("L2TP会话已经断开！")
}

func (l2tpSession *L2TPSession) StopCCN() {
	conn := l2tpSession.Conn
	l2tpSession.Ns++
	wbuff := StopCCN(l2tpSession.RTunnelId, l2tpSession.RSessionId, l2tpSession.Ns, l2tpSession.Nr, l2tpSession.LTunnelId)
	conn.Write(wbuff)
	log.Println("L2TP隧道已经断开！")
}
