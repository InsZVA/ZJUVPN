package protocol

import (
	"math/rand"
)

const (
	PPP_IP_DATA = 0x00
	PPP_LCP     = 0xc0
	PPP_CHAP    = 0xc2
	PPP_IPCP    = 0x80
	PPP_CONTROL = 0x80

	LCP_CONFIGURE_REQUEST   = 1
	LCP_CONFIGURE_ACK       = 2
	LCP_CONFIGURE_REJECT    = 4
	LCP_IDENTICAL           = 12
	LCP_TERMINATION_REQUEST = 5

	LCP_OPT_MAXIUM_RECEIVE_UNIT                   = 1
	LCP_OPT_AUTH_PROTOCOL                         = 3
	LCP_OPT_MAGIC_NUMBER                          = 5
	LCP_OPT_PROTOCOL_FIELD_COMPRESSION            = 7
	LCP_OPT_ADDRESS_AND_CONTROL_FIELD_COMPRESSION = 8
	LCP_OPT_CALLBACK                              = 13
	LCP_OPT_MULTILINK_MRRU                        = 17
	LCP_OPT_MULTILINK_ENDPOINT_DISCRIMINATOR      = 19

	CHAP_CHALLENGE = 1
	CHAP_RESPONSE  = 2
	CHAP_SUCCESS   = 3

	IPCP_CONFIGURE_REQUEST = 1
	IPCP_CONFIGURE_NAK     = 3
	IPCP_CONFIGURE_ACK     = 2

	IPCP_OPT_IP   = 3
	IPCP_OPT_PDNS = 129
	IPCP_OPT_SDNS = 131
)

func PPP(pppType byte, data []byte) []byte {
	ret := make([]byte, 4)
	ret[0] = 0xff
	ret[1] = 0x03
	ret[2] = pppType
	switch pppType {
	case PPP_IP_DATA:
		ret[3] = 0x21
	case PPP_LCP:
		ret[3] = 0x21
	case PPP_CHAP:
		ret[3] = 0x23
	case PPP_IPCP:
		ret[3] = 0x21
	}
	ret = append(ret, data...)
	return ret
}

func LCP(code byte, identical byte, data []byte) []byte {
	ret := make([]byte, 4)
	ret[0] = code
	ret[1] = identical
	length := len(data) + 4
	ret[2] = byte(length >> 8)
	ret[3] = byte(length)
	ret = append(ret, data[:length-4]...)
	return ret
}

func LCPOpt(lcpType byte, length byte, data []byte) []byte {
	ret := make([]byte, 2)
	ret[0] = lcpType
	ret[1] = length
	if length > 2 {
		ret = append(ret, data[:length-2]...)
	}
	return ret
}

func ConfigurationRequest0(identical byte, magic_number uint32) []byte {
	maxium_receive_unit := []byte{0x05, 0x78} // 1400
	buff := LCPOpt(LCP_OPT_MAXIUM_RECEIVE_UNIT, 4, maxium_receive_unit)

	magic_number_ := []byte{byte(magic_number >> 24), byte(magic_number >> 16),
		byte(magic_number >> 8), byte(magic_number)}
	buff = append(buff, LCPOpt(LCP_OPT_MAGIC_NUMBER, 6, magic_number_)...)

	buff = append(buff, LCPOpt(LCP_OPT_PROTOCOL_FIELD_COMPRESSION, 2, nil)...)

	buff = append(buff, LCPOpt(LCP_OPT_ADDRESS_AND_CONTROL_FIELD_COMPRESSION, 2, nil)...)

	buff = append(buff, LCPOpt(LCP_OPT_CALLBACK, 3, []byte{0x06})...)

	buff = append(buff, LCPOpt(LCP_OPT_MULTILINK_MRRU, 4, []byte{0x06, 0x4e})...)

	buff = append(buff, LCPOpt(LCP_OPT_MULTILINK_ENDPOINT_DISCRIMINATOR, 23,
		[]byte{0x01, 0xf2, 0x4d, 0x22, 0xf6, 0x53, 0x35, 0x4b, 0xb6, 0x9b, 0x87, 0x85, 0x5f,
			0xfd, 0xeb, 0x09, 0xad, 0x00, 0x00, 0x00, 0x03})...)

	return PPP(PPP_LCP, LCP(LCP_CONFIGURE_REQUEST, identical, buff))
}

func ConfigurationRequest(identical byte, magic_number uint32) []byte {
	maxium_receive_unit := []byte{0x05, 0x78} // 1400
	buff := LCPOpt(LCP_OPT_MAXIUM_RECEIVE_UNIT, 4, maxium_receive_unit)

	magic_number_ := []byte{byte(magic_number >> 24), byte(magic_number >> 16),
		byte(magic_number >> 8), byte(magic_number)}
	buff = append(buff, LCPOpt(LCP_OPT_MAGIC_NUMBER, 6, magic_number_)...)

	buff = append(buff, LCPOpt(LCP_OPT_PROTOCOL_FIELD_COMPRESSION, 2, nil)...)

	buff = append(buff, LCPOpt(LCP_OPT_ADDRESS_AND_CONTROL_FIELD_COMPRESSION, 2, nil)...)

	return PPP(PPP_LCP, LCP(LCP_CONFIGURE_REQUEST, identical, buff))
}

func ConfigurationAck1(identical byte, magic_number uint32) []byte {
	maxium_receive_unit := []byte{0x05, 0xa2} // 1442
	buff := LCPOpt(LCP_OPT_MAXIUM_RECEIVE_UNIT, 4, maxium_receive_unit)

	auths := []byte{0xc2, 0x23, 0x05}
	buff = append(buff, LCPOpt(LCP_OPT_AUTH_PROTOCOL, 5, auths)...)

	magic_number_ := []byte{byte(magic_number >> 24), byte(magic_number >> 16),
		byte(magic_number >> 8), byte(magic_number)}
	buff = append(buff, LCPOpt(LCP_OPT_MAGIC_NUMBER, 6, magic_number_)...)

	return PPP(PPP_LCP, LCP(LCP_CONFIGURE_ACK, identical, buff))
}

func Indentical(identical byte) []byte {
	buff := make([]byte, 4)
	buff[0] = LCP_IDENTICAL
	buff[1] = 0x00
	buff[2] = 0x00
	buff[3] = 0x1f
	buff = append(buff, 0x69, 0x0f, 0x6b, 0xda)
	buff = append(buff, []byte("MSRAS-0-LAPTOP-VQJUT1DJ")...)
	return PPP(PPP_LCP, buff)
}

func CHAP(code byte, identical byte, value []byte, name []byte) []byte {
	length := 5 + len(value) + len(name)
	ret := make([]byte, 5)
	ret[0] = code
	ret[1] = identical
	ret[2] = byte(length >> 8)
	ret[3] = byte(length)
	ret[4] = byte(len(value))
	ret = append(ret, value...)
	ret = append(ret, name...)
	return ret
}

func IPCP(code byte, identical byte, data []byte) []byte {
	length := 4 + len(data)
	ret := make([]byte, 4)
	ret[0] = code
	ret[1] = identical
	ret[2] = byte(length >> 8)
	ret[3] = byte(length)
	ret = append(ret, data...)
	return ret
}

func IPCPConfigureRequest0(identical byte) []byte {
	opts := make([]byte, 0)

	opts = append(opts, IPCP_OPT_IP, 6, 0x00, 0x00, 0x00, 0x00)
	opts = append(opts, IPCP_OPT_PDNS, 6, 0x00, 0x00, 0x00, 0x00)
	opts = append(opts, IPCP_OPT_SDNS, 6, 0x00, 0x00, 0x00, 0x00)

	return PPP(PPP_IPCP, IPCP(IPCP_CONFIGURE_REQUEST, identical, opts))
}

func IPCPConfigureRequest1(identical byte, ip []byte, pdns []byte, sdns []byte) []byte {
	opts := make([]byte, 0)

	opts = append(opts, IPCP_OPT_IP, 6)
	opts = append(opts, ip...)
	opts = append(opts, IPCP_OPT_PDNS, 6)
	opts = append(opts, pdns...)
	opts = append(opts, IPCP_OPT_SDNS, 6)
	opts = append(opts, sdns...)

	return PPP(PPP_IPCP, IPCP(IPCP_CONFIGURE_REQUEST, identical, opts))
}

func TerminationRequest(identical byte) []byte {
	buff := make([]byte, 4)
	buff[0] = LCP_TERMINATION_REQUEST
	buff[1] = identical
	buff[2] = 0
	buff[3] = 16
	for i := 0; i < 12; i++ {
		buff = append(buff, byte(rand.Uint32()>>24))
	}
	return PPP(PPP_LCP, buff)
}
