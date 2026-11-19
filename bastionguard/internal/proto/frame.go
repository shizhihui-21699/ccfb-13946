package proto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Frame types on the mTLS relay wire.
const (
	FrameHello    byte = 3 // JSON Hello, only the first frame of a connection
	FrameData     byte = 1 // raw tunnel bytes (SSH between worker and target)
	FrameControl  byte = 2 // Sealed control message for the laptop agent
	FrameTeardown byte = 4 // cleartext teardown command, laptop presence -> relay
)

const (
	MaxSessLen    = 64
	MaxDataFrame  = 32 * 1024
	MaxCtlFrame   = 1024 * 1024
	MaxHelloFrame = 64 * 1024
)

// Hello is the cleartext first frame of every connection to a relay. It is
// inside mTLS so node identity is already proven by the client certificate;
// it only tells the relay how to route this particular connection.
type Hello struct {
	Role    string   `json:"role"`              // "presence" | "client" | "relay"
	Node    string   `json:"node"`              // sender node id (must match cert CN)
	ConnID  string   `json:"conn_id"`           // relay routing id for THIS connection
	Session string   `json:"session,omitempty"` // logical agent session id (grant key)
	Zone    string   `json:"zone,omitempty"`    // target zone the session is bound to
	Target  string   `json:"target,omitempty"`  // requested host:port, validated by relay
	Chain   []string `json:"chain,omitempty"`   // relay node ids, entry first
}

// Frame is one routed frame. Session is a random opaque id used by relays for
// routing; it never reveals the target host.
type Frame struct {
	Type    byte
	Session string
	Payload []byte
}

// WriteFrame writes one length-prefixed frame.
func WriteFrame(w io.Writer, f Frame) error {
	if len(f.Session) > MaxSessLen {
		return errors.New("session id too long")
	}
	limit := MaxDataFrame
	if f.Type == FrameControl {
		limit = MaxCtlFrame
	}
	if f.Type == FrameHello {
		limit = MaxHelloFrame
	}
	if len(f.Payload) > limit {
		return fmt.Errorf("frame %d too large: %d > %d", f.Type, len(f.Payload), limit)
	}
	hdr := make([]byte, 0, 6+len(f.Session))
	hdr = append(hdr, f.Type, byte(len(f.Session)))
	hdr = append(hdr, f.Session...)
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(f.Payload)))
	hdr = append(hdr, l[:]...)
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	if len(f.Payload) > 0 {
		if _, err := w.Write(f.Payload); err != nil {
			return err
		}
	}
	return nil
}

// ReadFrame reads one frame.
func ReadFrame(r io.Reader) (Frame, error) {
	var first [2]byte
	if _, err := io.ReadFull(r, first[:]); err != nil {
		return Frame{}, err
	}
	typ := first[0]
	sessLen := int(first[1])
	if sessLen > MaxSessLen {
		return Frame{}, errors.New("bad session length")
	}
	sess := ""
	if sessLen > 0 {
		buf := make([]byte, sessLen)
		if _, err := io.ReadFull(r, buf); err != nil {
			return Frame{}, err
		}
		sess = string(buf)
	}
	var l [4]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return Frame{}, err
	}
	n := binary.BigEndian.Uint32(l[:])
	limit := uint32(MaxDataFrame)
	if typ == FrameControl {
		limit = MaxCtlFrame
	}
	if typ == FrameHello {
		limit = MaxHelloFrame
	}
	if n > limit {
		return Frame{}, fmt.Errorf("frame %d exceeds size limit", typ)
	}
	payload := make([]byte, n)
	if n > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return Frame{}, err
		}
	}
	return Frame{Type: typ, Session: sess, Payload: payload}, nil
}
