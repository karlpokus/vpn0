package packet

import "errors"

const Version = 2
const HeaderSize = 2

var ErrShortHeader = errors.New("short header")

type Header struct {
	Version uint8
	OpCode  OpCode
}

func (h Header) Marshal(dst []byte) {
	dst[0] = h.Version
	dst[1] = byte(h.OpCode)
}

func (h *Header) UnmarshalBinary(b []byte) error {
	if len(b) < 2 {
		return ErrShortHeader
	}
	h.Version = b[0]
	h.OpCode = OpCode(b[1])
	return nil
}
