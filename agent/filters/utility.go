package filters

import (
	"bytes"
	"encoding/binary"

	"github.com/iovisor/gobpf/bcc"
)

// one-liner for a
func readPerfEvent(eventData []byte, into interface{}) error {
	return binary.Read(
		bytes.NewBuffer(eventData),
		bcc.GetHostByteOrder(),
		into,
	)
}
