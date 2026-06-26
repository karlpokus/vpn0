package packet

import "errors"

var ErrShortFrame = errors.New("short frame")

type OpCode uint8

const (
	OpData OpCode = iota + 1
	//OpHandshakeInit
	//OpHandshakeResponse
	//OpRekey
	//OpError
)

type Frame struct {
	Header Header
	// Payload format is determined by Header.OpCode
	Payload []byte
}

// MarshalBinary returns the binary representation of itself.
//
// Wire format: header | payload
func (f Frame) MarshalBinary() ([]byte, error) {
	b := make([]byte, HeaderSize+len(f.Payload))
	f.Header.Marshal(b)
	copy(b[HeaderSize:], f.Payload)
	return b, nil
}

// UnmarshalBinary unmarshals a binary representation of itself.
func (f *Frame) UnmarshalBinary(data []byte) error {
	if len(data) < HeaderSize {
		return ErrShortFrame
	}
	if err := f.Header.UnmarshalBinary(data[:HeaderSize]); err != nil {
		return err
	}
	f.Payload = data[HeaderSize:]
	return nil
}

// ParseFrame parses data into a Frame and returns it.
//
// data is assumed to be raw wire format.
func ParseFrame(data []byte) (Frame, error) {
	var f Frame
	if err := f.UnmarshalBinary(data); err != nil {
		return Frame{}, err
	}
	return f, nil
}

// NewFrame creates-, and returns a new Frame from
// the provided input.
func NewFrame(op OpCode, payload []byte) Frame {
	return Frame{
		Header: Header{
			Version: Version,
			OpCode:  op,
		},
		Payload: payload,
	}
}
