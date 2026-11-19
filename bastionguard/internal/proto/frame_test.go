package proto

import (
	"bytes"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	cases := []Frame{
		{Type: FrameData, Session: "conn-1", Payload: []byte("ssh-banner\n")},
		{Type: FrameControl, Session: "conn-2", Payload: make([]byte, 4096)},
		{Type: FrameHello, Payload: []byte(`{"role":"presence"}`)},
		{Type: FrameTeardown, Payload: []byte("session-xyz")},
	}
	var buf bytes.Buffer
	for _, f := range cases {
		if err := WriteFrame(&buf, f); err != nil {
			t.Fatal(err)
		}
	}
	for _, want := range cases {
		got, err := ReadFrame(&buf)
		if err != nil {
			t.Fatal(err)
		}
		if got.Type != want.Type || got.Session != want.Session || !bytes.Equal(got.Payload, want.Payload) {
			t.Fatalf("frame mismatch: got=%+v want=%+v", got, want)
		}
	}
}
