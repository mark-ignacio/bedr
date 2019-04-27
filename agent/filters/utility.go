package filters

import (
	"time"
	"syscall"
	"unsafe"
	"bytes"
	"encoding/binary"

	"github.com/iovisor/gobpf/bcc"
)

var ktimeOffsetNS int64

// gives you an off-by-nanoseconds time to satiate humans
func ktime2Time(ktimeNS int64) time.Time {
	return time.Unix(0, ktimeNS + ktimeOffsetNS)
}

// one-liner for binary.Read
func readPerfEvent(eventData []byte, into interface{}) error {
	return binary.Read(
		bytes.NewBuffer(eventData),
		bcc.GetHostByteOrder(),
		into,
	)
}

func init() {
	var timespec syscall.Timespec
	syscall.Syscall(
		syscall.SYS_CLOCK_GETTIME, 
		1 /* CLOCK_MONOTONIC */, 
		uintptr(unsafe.Pointer(&timespec)),
		0,
	)
	ktimeOffsetNS = time.Now().UnixNano() - syscall.TimespecToNsec(timespec)
}