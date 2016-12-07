package protocol

import (
	"crypto/md5"
	"log"
)

const (
	PPP_LCP_CONSULT = iota
	PPP_CHAP_CONSULT
	PPP_IPCP_CONSULT
	PPP_CONNECTED
)

type PPPSession struct {
	L2tpSession  *L2TPSession
	LMagicNumber uint32
	RMagicNumber uint32
	LMRU         uint16
	RMRU         uint16
	AuthProtocol uint16
	Algotithm    byte
	Identical    byte
	Status       int
	Username     string
	Password     string
	IP           []byte
	PDNS         []byte
	SDNS         []byte
	Exit         chan bool
}

func (pppSession *PPPSession) ReadPPP(l2tpdata []byte) (ipData []byte) {
	if l2tpdata[0]&TYPE_CONTROL != 0 {
		log.Println("L2TP链路已经成功建立")
		pppSession.L2tpSession.SendData(ConfigurationRequest0(pppSession.Identical, pppSession.LMagicNumber))
		pppSession.Identical++
		return
	}
	headLength := 6
	if l2tpdata[0]&LENGTH_EXIST != 0 {
		headLength += 2
	}
	switch l2tpdata[headLength+2] {
	case PPP_LCP:
		pppSession.ReadLCP(l2tpdata[headLength+4:])
	case PPP_CHAP:
		pppSession.ReadCHAP(l2tpdata[headLength+4:])
	case PPP_IPCP:
		pppSession.ReadIPCP(l2tpdata[headLength+4:])
	case PPP_IP_DATA:
		ipData = l2tpdata[headLength+4:]
	}
	return
}

func (pppSession *PPPSession) ReadLCP(lcpData []byte) {
	switch lcpData[0] {
	case LCP_CONFIGURE_REQUEST:
		identical := lcpData[1]
		pos := 4
		for pos < int(lcpData[2])<<8|int(lcpData[3]) {
			lcpOptType := lcpData[pos]
			switch lcpOptType {
			case LCP_OPT_MAXIUM_RECEIVE_UNIT:
				pppSession.RMRU = uint16(lcpData[pos+2])<<8 | uint16(lcpData[pos+3])
				pos += 4
			case LCP_OPT_AUTH_PROTOCOL:
				pppSession.AuthProtocol = uint16(lcpData[pos+2])<<8 | uint16(lcpData[pos+3])
				pppSession.Algotithm = lcpData[pos+4]
				pos += 5
			case LCP_OPT_MAGIC_NUMBER:
				pppSession.RMagicNumber = uint32(lcpData[pos+2])<<24 | uint32(lcpData[pos+3])<<16 |
					uint32(lcpData[pos+4])<<8 | uint32(lcpData[pos+5])
				pos += 6
			default:
				pos += int(lcpData[pos+1])
			}
		}
		pppSession.L2tpSession.SendData(ConfigurationAck1(identical, pppSession.RMagicNumber))
	case LCP_CONFIGURE_REJECT:
	case LCP_CONFIGURE_ACK:
		pppSession.Status = PPP_CHAP_CONSULT
	}
}

func (ppp *PPPSession) LCPContact() {
	ppp.Status = PPP_LCP_CONSULT
	l2tpdata := make([]byte, 1500)
	ppp.L2tpSession.SendData(ConfigurationRequest0(ppp.Identical, ppp.LMagicNumber))
	ppp.Identical++
	// Server Request
	ppp.L2tpSession.Conn.Read(l2tpdata)
	ppp.ReadPPP(l2tpdata)
	// Server send ZLB
	ppp.L2tpSession.Conn.Read(l2tpdata)
	ppp.ReadPPP(l2tpdata)
	// Request1
	ppp.L2tpSession.SendData(ConfigurationRequest(ppp.Identical, ppp.LMagicNumber))
	ppp.Identical++
	// Send Identical
	ppp.L2tpSession.SendData(Indentical(ppp.Identical))
	ppp.Identical++
	// Server send ACK
	for ppp.Status == PPP_LCP_CONSULT {
		ppp.L2tpSession.Conn.Read(l2tpdata)
		ppp.ReadPPP(l2tpdata)
	}
}

func (pppSession *PPPSession) ReadCHAP(chapData []byte) {
	switch chapData[0] {
	case CHAP_CHALLENGE:
		identical := chapData[1]
		//length := int(chapData[2])<<8 | int(chapData[3])
		valueSize := chapData[4]
		value := chapData[5 : 5+valueSize]
		pppSession.CHAPResponse(identical, value)
	case CHAP_SUCCESS:
		log.Println("PPP认证成功!")
		pppSession.Status = PPP_IPCP_CONSULT
	}
}

func (ppp *PPPSession) CHAPResponse(identical byte, chall []byte) {
	h := md5.New()
	h.Write([]byte{identical})
	h.Write([]byte(ppp.Password))
	h.Write(chall)
	value := h.Sum(nil)
	ppp.L2tpSession.SendData(PPP(PPP_CHAP, CHAP(CHAP_RESPONSE, identical, value, []byte(ppp.Username))))
}

func (ppp *PPPSession) CHAPContact() {
	l2tpdata := make([]byte, 1500)
	for ppp.Status == PPP_CHAP_CONSULT {
		ppp.L2tpSession.Conn.Read(l2tpdata)
		ppp.ReadPPP(l2tpdata)
	}
}

func (ppp *PPPSession) ReadIPCP(ipcpData []byte) {
	switch ipcpData[0] {
	case IPCP_CONFIGURE_NAK:
		length := int(ipcpData[2])<<8 | int(ipcpData[3])
		// 针对ZJUVPN，简化处理了
		for i := 0; i < (length-4)/6; i++ {
			switch ipcpData[4+i*6] {
			case IPCP_OPT_IP:
				ppp.IP = ipcpData[4+i*6+2 : 4+i*6+6]
			case IPCP_OPT_PDNS:
				ppp.PDNS = ipcpData[4+i*6+2 : 4+i*6+6]
			case IPCP_OPT_SDNS:
				ppp.SDNS = ipcpData[4+i*6+2 : 4+i*6+6]
			}
		}
		ppp.L2tpSession.SendData(IPCPConfigureRequest1(ppp.Identical, ppp.IP, ppp.PDNS, ppp.SDNS))
		ppp.Identical++
	case IPCP_CONFIGURE_ACK:
	case IPCP_CONFIGURE_REQUEST:
		ipcpData[0] = IPCP_CONFIGURE_ACK
		length := int(ipcpData[2])<<8 | int(ipcpData[3])
		ppp.L2tpSession.SendData(PPP(PPP_IPCP, ipcpData[:length]))
		log.Println("链接已建立！")
		ppp.Status = PPP_CONNECTED
	}
}

func (ppp *PPPSession) IPCPContact() {
	ppp.L2tpSession.SendData(IPCPConfigureRequest0(ppp.Identical))
	ppp.Identical++
	l2tpdata := make([]byte, 1500)
	for ppp.Status == PPP_IPCP_CONSULT {
		ppp.L2tpSession.Conn.Read(l2tpdata)
		ppp.ReadPPP(l2tpdata)
	}
	/*ppp.L2tpSession.SendData(PPP(PPP_IP_DATA, []byte{0x00, 0x45, 0x0c, 0x9a, 0x00, 0x00, 0x40, 0x11, 0x68,
	0x92, 0xde, 0xcd, 0x1c, 0x90, 0x0a, 0x0a, 0x00, 0x15, 0xcf, 0xb0, 0x00, 0x35, 0x00, 0x31, 0xdb, 0xa4, 0x3d, 0x6c,
	0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77, 0x0f, 0x6d, 0x73, 0x66, 0x74, 0x63,
	0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x74, 0x65, 0x73, 0x74, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01}))
	*/
}

func (ppp *PPPSession) Terminate() {
	ppp.L2tpSession.SendData(TerminationRequest(ppp.Identical))
	ppp.L2tpSession.Conn.Read(make([]byte, 1500)) // Server send ACK
	log.Println("链接已经断开！")
}

func (ppp *PPPSession) SendIP(data []byte) {
	ppp.L2tpSession.SendData(PPP(PPP_IP_DATA, data))
}

func (ppp *PPPSession) ListenAndServe(handler func(data []byte)) {
	ppp.Exit = make(chan bool, 1)
LOOP:
	for {
		select {
		case <-ppp.Exit:
			break LOOP
		default:
		}
		buff := make([]byte, 2000)
		n, err := ppp.L2tpSession.Conn.Read(buff)
		if err != nil {
			log.Println(err)
			continue
		}
		ipdata := ppp.ReadPPP(buff[:n])
		if ipdata != nil && len(ipdata) != 0 {
			handler(ipdata)
		}
	}
}

func (ppp *PPPSession) StopListen() {
	ppp.Exit <- true
}
