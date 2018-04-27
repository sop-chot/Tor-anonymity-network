package cells

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"strconv"
	"strings"
)

// Spcification for cells and cells header
// Our specification of cells is similar to that of TOR's
// Reference: https://svn.torproject.org/svn/projects/design-paper/tor-design.html

// Cell
// A cell defines a byte/string slice that contains layers of encrypted data
// There are two kinds of cell: Control Cell and Relay Cell
//
//   Note that a cell is represented by a []byte/str
//   TOR design document states that there is a general header component that
//   is left unencrypted from the rest of the cell.
//   It contains CirID and CMD/Relay flag.
//   However, unlike TOR's cells our control and relay cells do not contain a common header.
//   Instead, this information is stored in a struct used to pass information into a RPC call
//   For details, please see resource.go in resource folder
//
//   MessageInfo {
//      RequesterAddr string
// 	 	CirID         string
//      isRelay       bool
//		EncryptedData []byte
//   }
//
//
//   Control Cell: create, created, destroy
//
//   Total: 512 bytes
//
//
//    1 byte      511 bytes
//   ===========================
//   |  CMD  |      DATA       |
//   ===========================
//
//   - Interpreted by the node that receives them
//   - The entire control cell [CMD - DATA] is encrypted
//   - A control cell consists of a CMD and DATA
//   - CMD refers to one of CREATE, CREATED, DESTROY
//   - Contents of DATA portion:
//   	- CREATE: contains OnionLib's generated half of DH key for key exhange
//   	- CREATED: nil
//   	- DESTROY: nil
//
//
//   Relay Cell:
//
//   Total of: 512 bytes (we can increase the size if this is too small, just change CellLength constant)
//
//    1 byte      2 bytes       16 bytes        2 bytes        491 bytes
//   =======================================================================
//   |  CMD  |   StreamID   |    Digest    |    Length    |      DATA      |
//   =======================================================================
//
//   - Carries end to end stream data
//   - The entire relay cell [CMD - StreamID - Digest - DATA] is encrypted with a shared key
//   - CMD will be a realy command, one of OnionCommand but none of create, created or destroy
//   - StreamID indicates the streamID this command
//   - Digest is a hash of DATA
//     - An onion router will check whether the hash of DATA matches the Digest field
//     - If it does then it decodes all other fields and process the packet
//     - If it doesn't then the onion node passes the decrypted onion packet on to the next node
//
//   Special Cases for some Commands:
//
//   EXTEND: In this case, the payload consists of [Target + Target^pubK(half DH key)]
//           Target indicates the address of onion node that need to be extended to (key exchange)
//           - Target is set to 6 bytes of zero for all node that is not the immediate predeccessor of the target
//
//    1 byte      2 bytes       16 bytes        2 bytes                   491 bytes
//   =================================================================================================
//   |  CMD  |   StreamID   |    Digest    |    Length    | Target + Encrypted 1/2 DH key to Target  |
//   =================================================================================================
//
//
//   TRUNCATE: Target indicates the address of onion node that need to be truncated
//             - Target is set to 6 bytes of zero for all node that is not the immediate predeccessor of the target
//
//    1 byte      2 bytes       16 bytes        2 bytes   491 bytes
//   ===============================================================
//   |  CMD  |   StreamID   |    Digest    |    Length    | Target |
//   ===============================================================
//
//
//   RESPONSE: PacketNumber indicates the sequence number of this response packet
//             PacketTotal  indicates the total number of response packets for this Data command Response
//             ResponseData a chunk of the actual data returned from the destination
//
//    1 byte      2 bytes       16 bytes        2 bytes       2 bytes        2 bytes       487 bytes
//   ===================================================================================================
//   |  CMD  |   StreamID   |    Digest    |    Length    | PacketNumber |  PacketTotal | ResponseData |
//   ===================================================================================================

// OnionCommand ... type representing commands allowed for circuit creation,
// relaying onion packages, and circuit termination
type OnionCommand int

// Implementation of OnionCommand
const (
	/****** Control Commands ******/

	// Initialize as a circuit node, create key for DH handshake
	CREATE = OnionCommand(iota)
	// Response to CREATE command indicating that
	// key creation is successful
	CREATED

	// Circuit termination
	DESTROY

	/****** Relay Commands ******/

	// Extends a circuit to a target
	EXTEND
	// Reponse to EXTEND command indicating that
	// circuit extension is sucessful
	EXTENDED

	// Delete a node from the circuit
	TRUNCATE
	// Response to TRUNCATE command indicating that
	// truncation is sucessful
	TRUNCATED

	// Initialize a TCP stream
	BEGIN
	// Response to BEGIN indicating that TCP stream is
	// established sucessfully
	CONNECTED

	// Sends a HTTP/HTTPS request to the destination
	DATA
	// Reponse to DATA containing "data" response from the destination
	RESPONSE

	// Closes a TCP stream
	END

	// When an error occurs connecting to a website
	TEARDOWN

	// For default case
	UNKNOWN
)

// Constants for fixed length cell sizes
const (
	CmdLength      = 1
	StreamIDLength = 2
	DigestLength   = 16
	PayloadLength  = 2

	CellLength        = 512
	ControlDataLength = CellLength - CmdLength - PayloadLength
	RelayDataLength   = CellLength - CmdLength - StreamIDLength - DigestLength - PayloadLength

	TargetLength = 6
	IPLength     = 4
	PortLength   = 2

	PacketNumberLength = 2
)

// ControlCell ... represents a decoded control cell
type ControlCell struct {
	Command OnionCommand
	Data    []byte
}

// RelayCell ... represents a decoded relay cell
type RelayCell struct {
	Command       OnionCommand
	StreamID      string
	Digest        []byte
	PayloadLength int
	// TODO: can refactor to store relay payload struct instead
	Target string
	Data   []byte
}

// DataPacket ... represents a decoded payload of a DATA command response
type DataPacket struct {
	PacketNumber int
	PacketTotal  int
	Data         []byte
}

// EncodeControlCell ... returns a control cell
func EncodeControlCell(cmd OnionCommand, data []byte) []byte {
	var buf bytes.Buffer
	buf.WriteByte(EncodeControlCmd(cmd))
	buf.Write(EncodeBytesWithPadding(data, ControlDataLength))
	return buf.Bytes()
}

// DecodeControlCell ... decodes control cell and returns a ControlCell struct
func DecodeControlCell(decryptedCell []byte) ControlCell {
	cmd := DecodeCommand(decryptedCell)
	data := DecodeControlData(decryptedCell)
	return ControlCell{
		Command: cmd,
		Data:    data,
	}
}

// EncodeRelayCell ... returns a relay cell
// if command is EXTEND/TRUNCATE
//    - pass in target ip:port through target AND
//    - pass in half DH key encrypted with target's public key through data
// else
//    - pass in "" (empty string) for target AND
//    - pass in payload through data
func EncodeRelayCell(cmd OnionCommand, streamID, target string, data []byte) []byte {
	bCmd := EncodeRelayCmd(cmd)
	bStreamID := EncodeStringWithPadding(streamID, StreamIDLength)
	bTarget := EncodeAddr(target)
	var bPayloadLength []byte
	var bPayload []byte
	if cmd == EXTEND || cmd == TRUNCATE || cmd == TRUNCATED {
		bPayloadLength = Encode16BitsInt(len(data) + TargetLength)
		bPayload = append(bTarget, data...)
	} else {
		bPayloadLength = Encode16BitsInt(len(data))
		bPayload = data
	}
	bPayload = EncodeBytesWithPadding(bPayload, RelayDataLength)
	bDigest := EncodePayloadDigest(bPayload)

	var buf bytes.Buffer
	buf.WriteByte(bCmd)
	buf.Write(bStreamID)
	buf.Write(bDigest)
	buf.Write(bPayloadLength)
	buf.Write(bPayload)
	return buf.Bytes()
}

// DecodeRelayCell ... decodes control cell and returns a ControlCell struct
func DecodeRelayCell(decryptedCell []byte) RelayCell {
	cmd := DecodeCommand(decryptedCell)
	streamID := DecodeStreamID(decryptedCell)
	digest := DecodePayloadDigest(decryptedCell)
	payloadLength := DecodePayloadLength(decryptedCell)
	var target string
	if cmd == EXTEND || cmd == TRUNCATE || cmd == TRUNCATED {
		target = DecodeRelayTarget(decryptedCell, payloadLength)
	} else {
		target = ""
	}
	data := DecodeRelayData(decryptedCell, cmd, payloadLength)

	return RelayCell{
		Command:       cmd,
		StreamID:      streamID,
		Digest:        digest,
		PayloadLength: payloadLength,
		Target:        target,
		Data:          data,
	}
}

// EncodeDataResponsePayload ... method to encode the payload for a DATA command response
func EncodeDataResponsePayload(packetNumber int, packetTotal int, data []byte) []byte {
	pn := make([]byte, 8)
	binary.BigEndian.PutUint64(pn, uint64(packetNumber))
	pt := make([]byte, 8)
	binary.BigEndian.PutUint64(pt, uint64(packetTotal))

	var buf bytes.Buffer
	buf.WriteByte(pn[6])
	buf.WriteByte(pn[7])
	buf.WriteByte(pt[6])
	buf.WriteByte(pt[7])
	buf.Write(data)
	return buf.Bytes()
}

// DecodeDataResponsePayload ... method to decode the payload for a DATA command response
func DecodeDataResponsePayload(payload []byte) DataPacket {
	b := make([]byte, 8)
	for i := 0; i < 6; i++ {
		b[i] = byte(0)
	}
	b[6] = payload[0]
	b[7] = payload[1]
	pn := binary.BigEndian.Uint64(b)
	b[6] = payload[2]
	b[7] = payload[3]
	pt := binary.BigEndian.Uint64(b)
	data := payload[4:]
	return DataPacket{
		PacketNumber: int(pn),
		PacketTotal:  int(pt),
		Data:         data,
	}
}

// IsDigestValid ... Checks if digest matches MD5 checksum of payload
func IsDigestValid(decryptedCell []byte) bool {

	if len(decryptedCell) != 512 {
		return false
	}
	digest := DecodePayloadDigest(decryptedCell)
	payload := DecodeRelayPayload(decryptedCell)
	sum := md5.Sum(payload)

	for i := 0; i < DigestLength; i++ {
		if digest[i] != sum[i] {
			return false
		}
	}

	return true
}

// IsRelayCellDigestValid ... Checks if digest matches MD5 checksum of payload
func IsRelayCellDigestValid(relayCell RelayCell) bool {
	return false
}

/************************* Helper Methods *************************/
// Note: These helper methods are also exposed, feel free to use them individually

// EncodeControlCmd ... matches onion command with its corresponding byte calue
func EncodeControlCmd(cmd OnionCommand) byte {
	switch cmd {
	case CREATE:
		return byte(0)
	case CREATED:
		return byte(1)
	case DESTROY:
		return byte(2)
	default:
		return byte(13)
	}
}

// EncodeRelayCmd .. matches onion command with corresponding byte value
func EncodeRelayCmd(cmd OnionCommand) byte {
	switch cmd {
	case EXTEND:
		return byte(3)
	case EXTENDED:
		return byte(4)
	case TRUNCATE:
		return byte(5)
	case TRUNCATED:
		return byte(6)
	case BEGIN:
		return byte(7)
	case CONNECTED:
		return byte(8)
	case DATA:
		return byte(9)
	case RESPONSE:
		return byte(10)
	case END:
		return byte(11)
	case TEARDOWN:
		return byte(12)
	default:
		return byte(13)
	}
}

// EncodeAddr ... encodes string ip:port address into 6 bytes
func EncodeAddr(address string) []byte {
	if address == "" {
		// return an empty []byte if address passed in is empty
		return make([]byte, 6)
	}

	var buf bytes.Buffer
	addr := strings.Split(address, ":")

	// Encode IP
	ip := strings.Trim(addr[0], ":")
	octets := strings.Split(ip, ".")
	for _, octet := range octets {
		i, _ := strconv.Atoi(octet)
		buf.WriteByte(byte(i))
	}

	// Encode Port
	port := addr[1]
	i, _ := strconv.ParseUint(port, 10, 64)
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, i)
	buf.WriteByte(b[6])
	buf.WriteByte(b[7])

	return buf.Bytes()
}

// DecodeAddr ... decodes 6 bytes ip:port address into a string representation
func DecodeAddr(address []byte) string {
	var stringAddr string
	var ip []byte
	var port []byte

	ip = address[:4]
	port = address[4:]

	// Decode IP
	for index, octet := range ip {
		stringAddr = stringAddr + strconv.Itoa(int(octet))
		if index != 3 {
			stringAddr += "."
		}
	}
	stringAddr += ":"

	// Decode Port
	b := make([]byte, 8)
	for i := 0; i < 6; i++ {
		b[i] = byte(0)
	}
	b[6] = port[0]
	b[7] = port[1]
	p := binary.BigEndian.Uint64(b)
	stringAddr += strconv.FormatUint(p, 10)
	//fmt.Println("Complete IP:", stringAddr)
	return stringAddr
}

// Encode16BitsInt ... encode an integer into 2 bytes(16 bits)
func Encode16BitsInt(n int) []byte {
	var buf bytes.Buffer
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(n))
	buf.WriteByte(b[6])
	buf.WriteByte(b[7])
	return buf.Bytes()
}

// Decode16BitsInt ... encode an integer into 2 bytes(16 bits)
func Decode16BitsInt(n []byte) int {
	b := make([]byte, 8)
	for i := 0; i < 6; i++ {
		b[i] = byte(0)
	}
	b[6] = n[0]
	b[7] = n[1]
	return int(binary.BigEndian.Uint64(b))
}

// EncodeStringWithPadding ... encodes a string with padding 0 in front in case it's too short
func EncodeStringWithPadding(data string, targetLength int) []byte {
	var buf bytes.Buffer

	if len(data) < targetLength {
		for i := 0; i < targetLength-len(data); i++ {
			buf.WriteByte(0)
		}
	}

	buf.Write([]byte(data))
	return buf.Bytes()
}

// EncodeBytesWithPadding ... encodes a []byte with padding 0 in front in case it's too short
func EncodeBytesWithPadding(data []byte, targetLength int) []byte {
	var buf bytes.Buffer

	for i := 0; i < targetLength-len(data); i++ {
		buf.WriteByte(0)
	}

	buf.Write(data)
	return buf.Bytes()
}

// DecodeCommand ... returns the command
func DecodeCommand(cell []byte) OnionCommand {
	switch cell[0] {
	case byte(0):
		return CREATE
	case byte(1):
		return CREATED
	case byte(2):
		return DESTROY
	case byte(3):
		return EXTEND
	case byte(4):
		return EXTENDED
	case byte(5):
		return TRUNCATE
	case byte(6):
		return TRUNCATED
	case byte(7):
		return BEGIN
	case byte(8):
		return CONNECTED
	case byte(9):
		return DATA
	case byte(10):
		return RESPONSE
	case byte(11):
		return END
	case byte(12):
		return TEARDOWN
	default:
		return UNKNOWN
	}
}

// DecodeStreamID ... Get streamID
func DecodeStreamID(decryptedCell []byte) string {
	start := CmdLength
	end := start + StreamIDLength
	return string(decryptedCell[start:end])
}

// DecodePayloadDigest ... return decoded digest length
func DecodePayloadDigest(decryptedCell []byte) []byte {
	start := CmdLength + StreamIDLength
	end := start + DigestLength
	return decryptedCell[start:end]
}

// DecodePayloadLength ... return decoded payload length
func DecodePayloadLength(decryptedCell []byte) int {
	start := CmdLength + StreamIDLength + DigestLength
	end := start + PayloadLength
	return Decode16BitsInt(decryptedCell[start:end])
}

// DecodeRelayTarget ... return relay target
func DecodeRelayTarget(decryptedCell []byte, payloadLength int) string {
	start := CmdLength + StreamIDLength + DigestLength + PayloadLength + (RelayDataLength - payloadLength)
	payload := decryptedCell[start:]
	end := TargetLength
	return DecodeAddr(payload[:end])
}

// DecodeControlData ... Get the onion portion of DATA to pass to the next onion node
func DecodeControlData(decryptedCell []byte) []byte {
	start := CmdLength
	data := decryptedCell[start:]
	return data
}

// DecodeRelayData ... Get the payload portion of the cell
// In the case of payload for EXTEND/TRUNCATE
// it does not retrieve Target, it only retrieves the payload portion encrypted with Target's public key
// use DecodeRelayTarget to retrieve Target
func DecodeRelayData(decryptedCell []byte, cmd OnionCommand, payloadLength int) []byte {
	var start int
	if cmd == EXTEND || cmd == TRUNCATE {
		start = CmdLength + StreamIDLength + DigestLength + PayloadLength + (RelayDataLength - payloadLength) + TargetLength
	} else {
		start = CmdLength + StreamIDLength + DigestLength + PayloadLength + (RelayDataLength - payloadLength)
	}
	data := decryptedCell[start:]
	return data
}

// DecodeRelayPayload .. returns entire payload
// In the case of EXTEND/TRUNCATE, it returns target + target public key encrypted data
func DecodeRelayPayload(decryptedCell []byte) []byte {
	start := CmdLength + StreamIDLength + DigestLength + PayloadLength
	data := decryptedCell[start:]
	return data
}

// EncodePayloadDigest ... Calculate payload digest and encode it in bytes
func EncodePayloadDigest(data []byte) []byte {
	sum := md5.Sum(data)
	return sum[:]
}
