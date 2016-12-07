package protocol

import (
	"errors"
)

const (
	// Byte 0
	TYPE_DATA      = 0
	TYPE_CONTROL   = 1 << 7
	LENGTH_EXIST   = 1 << 6
	SEQUENCE_EXIST = 1 << 3 // Control Must
	OFFSET_EXIST   = 1 << 1 // Control Mustn't
	PRIORITY       = 1 << 0 // Control Mustn't
	// Byte 1
	VERSION = 2
	// Byte 2-3: Length
	// Byte 4-5: TunnelID
	/* Tunnel ID：标识L2TP控制链接，L2TP Tunnel标识符只有本地意义，
	一个Tunnel两端被分配的Tunnel ID可能会不同，报头中的Tunnel是指接收方的Tunnel ID，
	而不是发送方的。本端的Tunnel ID在创建Tunnel时分配。
	通过Tunnel ID AVPs和对端交换Tunnel ID信息。*/
	// Byte 6-7: SessionID
	/* Session ID：标识Tunnel中的一个session，只有本地意义，一个session两端Session ID可能不同。*/
	// Byte 8-9: Ns：标识发送数据或控制消息的序号，从0开始，以1递增，到216再从0开始
	// Byte 10-11: Nr：标识下一个期望接收到的控制消息。Nr的值设置成上一个接收到的控制消息的Ns+1。这样是对上一个接收到的控制消息的确认。数据消息忽略Nr
	// Byte 12-13: Offset Size：如果值存在的话，标识有效载荷数据的偏移。

	//AVP
	// Byte 0
	MANDATORY = 1 << 7 /* (M)命令位：用来控制收到不认识的AVP时必须执行的动作。
	如果在一个关联特殊的会话消息中M位被置为不认识的AVP，这个会话一定会被终止。
	如果在一个关联全部通道的消息中M位被置为不认识的AVP，整个通道包括通道内的会话一定会被终止。
	如果M为没有被设置，这个不认识的AVP会被忽略掉。*/
	HIDDEN = 1 << 3 // (H)隐藏位：用来识别一个AVP的属性域里的隐藏数据。
	// Byte 1 Length
	// Byte 2-3 Vender ID
	// Byte 4-5 Attribute Type
	AVP_CONTROL_MESSAGE  = 0
	PROTOCOL_VERSION     = 2
	FRAMING_CAPABILITIES = 3
	BEARER_CAPABILITIES  = 4
	FIRMWARE_REVISION    = 6
	HOST_NAME            = 7
	VENDOR_NAME          = 8
	ASSIGNED_TUNNEL_ID   = 9
	RECEIVE_WINDOW_SIZE  = 10
	ASSIGNED_SESSION     = 14
	CALL_SERIAL_NUMBER   = 15
	BEAR_TYPE            = 18
	FRAMING_TYPE         = 19
	CONNECT_SPEED        = 24
	PROXY_AUTHEN_TYPE    = 29
	RESULR_ERROR_CODE    = 1
	// Byte 6-7 Attribute Value
	START_CONTROL_REQUEST   = 1
	START_CONTROL_REPLY     = 2
	START_CONTROL_CONNECTED = 3
	INCOMING_CALL_REQUEST   = 10
	INCOMING_CALL_REPLY     = 11
	INCOMING_CALL_CONNECTED = 12
)

func AVPPacket(bits2 byte, length uint16, vendorId uint16, attrType uint16, attrValue []byte) []byte {
	buff := make([]byte, 6)
	buff[0] = bits2 | byte((length&0x3ff)>>8)
	buff[1] = byte(length)
	buff[2] = byte(vendorId >> 8)
	buff[3] = byte(vendorId)
	buff[4] = byte(attrType >> 8)
	buff[5] = byte(attrType)
	buff = append(buff, attrValue[:length-6]...)
	return buff
}

func L2TPControlHEAD(tunnelId uint16, sessionId uint16, ns uint16, nr uint16) []byte {
	buff := make([]byte, 12)
	buff[0] = TYPE_CONTROL | LENGTH_EXIST | SEQUENCE_EXIST
	buff[1] = VERSION
	buff[2] = 0
	buff[3] = 12
	buff[4] = byte(tunnelId >> 8)
	buff[5] = byte(tunnelId)
	buff[6] = byte(sessionId >> 8)
	buff[7] = byte(sessionId)
	buff[8] = byte(ns >> 8)
	buff[9] = byte(ns)
	buff[10] = byte(nr >> 8)
	buff[11] = byte(nr)
	return buff
}

func SCCRQ(hostname string, vendorname string, assigned_tunnel_id uint16, receive_window_size uint16) []byte {
	buff := L2TPControlHEAD(0, 0, 0, 0)

	// Control Message AVP
	start_control_request := []byte{0, 1}
	buff = append(buff, AVPPacket(MANDATORY, 8, 0, AVP_CONTROL_MESSAGE, start_control_request)...)
	// Protocol Version AVP
	versions := []byte{1, 0}
	buff = append(buff, AVPPacket(MANDATORY, 8, 0, PROTOCOL_VERSION, versions)...)
	// Framing Capabilities AVP
	sync_framing_support := byte(1 << 0)
	buff = append(buff, AVPPacket(MANDATORY, 10, 0, FRAMING_CAPABILITIES, []byte{0, 0, 0, sync_framing_support})...)
	// Bearer Capabilities AVP
	buff = append(buff, AVPPacket(MANDATORY, 10, 0, BEARER_CAPABILITIES, []byte{0, 0, 0, 0})...)
	// Firmware Revision AVP
	firmware_rivision := []byte{0x0a, 0x00}
	buff = append(buff, AVPPacket(0, 8, 0, FIRMWARE_REVISION, firmware_rivision)...)
	// Host Name AVP
	hostname_ := []byte(hostname)
	buff = append(buff, AVPPacket(MANDATORY, uint16(len(hostname_)+6), 0, HOST_NAME, hostname_)...)
	// Vendor Name AVP
	vendername_ := []byte(vendorname)
	buff = append(buff, AVPPacket(0, uint16(len(vendorname)+6), 0, VENDOR_NAME, vendername_)...)
	// Assigned Tunnel ID AVP
	assigned_tunnel_id_ := []byte{byte(assigned_tunnel_id >> 8), byte(assigned_tunnel_id)}
	buff = append(buff, AVPPacket(MANDATORY, 8, 0, ASSIGNED_TUNNEL_ID, assigned_tunnel_id_)...)
	// Receive Window Size AVP
	receive_window_size_ := []byte{byte(receive_window_size >> 8), byte(receive_window_size)}
	buff = append(buff, AVPPacket(MANDATORY, 8, 0, RECEIVE_WINDOW_SIZE, receive_window_size_)...)
	buff[2] = byte(len(buff) >> 8)
	buff[3] = byte(len(buff))
	return buff
}

type SCCRP struct {
	ZLB
	Version             byte
	Reversion           byte
	Hostname            string
	AsyncFramingSupport bool
	SyncFramingSupport  bool
	AssignedTunnelId    uint16
	ReceiveWindowSize   uint16
	FirmwareRevision    uint16
	VendorName          string
}

func ReadSCCRP(l2tpData []byte) (ret SCCRP, err error) {
	length := uint16(l2tpData[2])<<8 | uint16(l2tpData[3])
	l2tpData = l2tpData[:length]
	ret.TunnelId = uint16(l2tpData[4])<<8 | uint16(l2tpData[5])
	ret.SessionId = uint16(l2tpData[6])<<8 | uint16(l2tpData[7])
	ret.Ns = uint16(l2tpData[8])<<8 | uint16(l2tpData[9])
	ret.Nr = uint16(l2tpData[10])<<8 | uint16(l2tpData[11])

	pos := 12
	for l2tpData = l2tpData[pos:]; len(l2tpData) > 0; l2tpData = l2tpData[pos:] {
		pos, err = ret.ReadAVP(l2tpData)
		if err != nil {
			return
		}
	}
	return
}

func (sccrp *SCCRP) ReadAVP(AVPData []byte) (nextReadPos int, err error) {
	length := (int(AVPData[0])&0x3)<<2 | int(AVPData[1])
	if length > len(AVPData) || length < 8 {
		err = errors.New("ReadAVP: data is broken")
		return
	}
	nextReadPos = int(length)
	switch int(AVPData[4])<<8 | int(AVPData[5]) {
	case AVP_CONTROL_MESSAGE:
		if len(AVPData) < 8 || length < 8 ||
			AVPData[6]<<8|AVPData[7] != 2 { // start_control_reply
			err = errors.New("Excepted: start_control_reply")
		}
	case PROTOCOL_VERSION:
		sccrp.Version = AVPData[6]
		sccrp.Reversion = AVPData[7]
	case HOST_NAME:
		sccrp.Hostname = string(AVPData[6:length])
	case FRAMING_CAPABILITIES:
		if len(AVPData) < 10 {
			err = errors.New("ReadAVP: framing data is broken")
			return
		}
		if AVPData[9]&0x2 != 0 {
			sccrp.AsyncFramingSupport = true
		}
		if AVPData[9]&0x1 != 0 {
			sccrp.SyncFramingSupport = true
		}
	case ASSIGNED_TUNNEL_ID:
		sccrp.AssignedTunnelId = uint16(AVPData[6])<<8 | uint16(AVPData[7])
	case RECEIVE_WINDOW_SIZE:
		sccrp.ReceiveWindowSize = uint16(AVPData[6])<<8 | uint16(AVPData[7])
	case FIRMWARE_REVISION:
		sccrp.FirmwareRevision = uint16(AVPData[6])<<8 | uint16(AVPData[7])
	case VENDOR_NAME:
		sccrp.VendorName = string(AVPData[6:length])
	}
	return
}

func SCCCN(tunnelId uint16, sessionId uint16, ns uint16, nr uint16) []byte {
	buff := L2TPControlHEAD(tunnelId, sessionId, ns, nr)

	// Control Message AVP
	start_control_connected := []byte{0, 3}
	buff = append(buff, AVPPacket(MANDATORY, 8, 0, AVP_CONTROL_MESSAGE, start_control_connected)...)

	buff[2] = byte(len(buff) >> 8)
	buff[3] = byte(len(buff))
	return buff
}

type ZLB struct {
	TunnelId  uint16
	SessionId uint16
	Ns        uint16
	Nr        uint16
}

func ReadZLB(l2tpData []byte) (ret ZLB) {
	ret.TunnelId = uint16(l2tpData[4])<<8 | uint16(l2tpData[5])
	ret.SessionId = uint16(l2tpData[6])<<8 | uint16(l2tpData[7])
	ret.Ns = uint16(l2tpData[8])<<8 | uint16(l2tpData[9])
	ret.Nr = uint16(l2tpData[10])<<8 | uint16(l2tpData[11])
	return
}

func ICRQ(tunnelId uint16, sessionId uint16, ns uint16, nr uint16, assigned_session_id uint16,
	call_serial_number uint32) []byte {
	buff := L2TPControlHEAD(tunnelId, sessionId, ns, nr)

	// Control Message AVP
	incoming_call_request_ := []byte{0, 10}
	buff = append(buff, AVPPacket(MANDATORY, 8, 0, AVP_CONTROL_MESSAGE, incoming_call_request_)...)

	// Assigned Session AVP
	assigned_sission_id_ := []byte{byte(assigned_session_id >> 8), byte(assigned_session_id)}
	buff = append(buff, AVPPacket(MANDATORY, 8, 0, ASSIGNED_SESSION, assigned_sission_id_)...)

	// Call Serial Number AVP
	call_serial_number_ := []byte{byte(call_serial_number >> 24), byte(call_serial_number >> 16),
		byte(call_serial_number >> 8), byte(call_serial_number)}
	buff = append(buff, AVPPacket(MANDATORY, 10, 0, CALL_SERIAL_NUMBER, call_serial_number_)...)

	// Bearer Type AVP
	analog_bearer_type := []byte{0, 0, 0, 2}
	buff = append(buff, AVPPacket(MANDATORY, 10, 0, BEAR_TYPE, analog_bearer_type)...)

	buff[2] = byte(len(buff) >> 8)
	buff[3] = byte(len(buff))
	return buff
}

type ICRP struct {
	ZLB
	AssignedSessionId uint16
}

func (icrp *ICRP) ReadAVP(l2tpData []byte) (nextReadPos int, err error) {
	length := (int(l2tpData[0])&0x3)<<2 | int(l2tpData[1])
	if length > len(l2tpData) || length < 8 {
		err = errors.New("ReadAVP: data is broken")
		return
	}
	nextReadPos = int(length)
	switch int(l2tpData[4])<<8 | int(l2tpData[5]) {
	case AVP_CONTROL_MESSAGE:
		if len(l2tpData) < 8 || length < 8 ||
			l2tpData[6]<<8|l2tpData[7] != 11 { // incoming_call_reply
			err = errors.New("Excepted: incoming_call_reply")
		}
	case ASSIGNED_SESSION:
		icrp.AssignedSessionId = uint16(l2tpData[6])<<8 | uint16(l2tpData[7])
	}
	return
}

func ReadICRP(l2tpData []byte) (ret ICRP, err error) {
	length := uint16(l2tpData[2])<<8 | uint16(l2tpData[3])
	l2tpData = l2tpData[:length]
	ret.ZLB = ReadZLB(l2tpData)
	pos := 12
	for l2tpData = l2tpData[pos:]; len(l2tpData) > 0; l2tpData = l2tpData[pos:] {
		pos, err = ret.ReadAVP(l2tpData)
		if err != nil {
			return
		}
	}
	return
}

func ICCN(tunnelId uint16, sessionId uint16, ns uint16, nr uint16) []byte {
	buff := L2TPControlHEAD(tunnelId, sessionId, ns, nr)

	// Control Message AVP
	incoming_call_connected_ := []byte{0, 12}
	buff = append(buff, AVPPacket(MANDATORY, 8, 0, AVP_CONTROL_MESSAGE, incoming_call_connected_)...)

	// Connect Speed AVP
	connect_speed_ := []byte{0x05, 0xf5, 0xe1, 0x00} // 100Mbps
	buff = append(buff, AVPPacket(MANDATORY, 10, 0, CONNECT_SPEED, connect_speed_)...)

	// Framing Type AVP
	sync_framing_support := []byte{0, 0, 0, 1}
	buff = append(buff, AVPPacket(MANDATORY, 10, 0, FRAMING_TYPE, sync_framing_support)...)

	// Proxy Authen Type AVP
	no_authen := []byte{0, 4}
	buff = append(buff, AVPPacket(MANDATORY, 8, 0, PROXY_AUTHEN_TYPE, no_authen)...)

	buff[2] = byte(len(buff) >> 8)
	buff[3] = byte(len(buff))
	return buff
}

func CDN(tunnelId uint16, sessionId uint16, ns uint16, nr uint16, assigned_session_id uint16) []byte {
	buff := L2TPControlHEAD(tunnelId, sessionId, ns, nr)

	// Control Message AVP
	call_disconnected_notification_ := []byte{0, 14}
	buff = append(buff, AVPPacket(MANDATORY, 8, 0, AVP_CONTROL_MESSAGE, call_disconnected_notification_)...)

	// Result Error AVP
	disconnected_for_administrative_reasons_ := []byte{0, 3, 0, 0}
	buff = append(buff, AVPPacket(MANDATORY, 10, 0, RESULR_ERROR_CODE, disconnected_for_administrative_reasons_)...)

	// Assigned Session AVP
	assigned_sission_id_ := []byte{byte(assigned_session_id >> 8), byte(assigned_session_id)}
	buff = append(buff, AVPPacket(MANDATORY, 8, 0, ASSIGNED_SESSION, assigned_sission_id_)...)

	buff[2] = byte(len(buff) >> 8)
	buff[3] = byte(len(buff))
	return buff
}

func StopCCN(tunnelId uint16, sessionId uint16, ns uint16, nr uint16, assigned_tunnel_id uint16) []byte {
	buff := L2TPControlHEAD(tunnelId, sessionId, ns, nr)

	// Control Message AVP
	stop_control_notification_ := []byte{0, 4}
	buff = append(buff, AVPPacket(MANDATORY, 8, 0, AVP_CONTROL_MESSAGE, stop_control_notification_)...)

	// Assigned Tunnel ID AVP
	assigned_tunnel_id_ := []byte{byte(assigned_tunnel_id >> 8), byte(assigned_tunnel_id)}
	buff = append(buff, AVPPacket(MANDATORY, 8, 0, ASSIGNED_TUNNEL_ID, assigned_tunnel_id_)...)

	// Result Error AVP
	requester_is_being_shut_down := []byte{0, 6, 0, 0}
	buff = append(buff, AVPPacket(MANDATORY, 10, 0, RESULR_ERROR_CODE, requester_is_being_shut_down)...)

	buff[2] = byte(len(buff) >> 8)
	buff[3] = byte(len(buff))
	return buff
}
