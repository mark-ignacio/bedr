package filters

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/iovisor/gobpf/bcc"
)

// PacketFilter ensures the universality of start/stopping BPFs.
type PacketFilter interface {
	// NewModule attaches
	Listen(ctx context.Context) error
	// Attached returns whether the tracepoint/whatever is attached
	Attached() bool
}

// PacketFilterEvent is (generally) what all BPF event structs should embed, for interop's sake.
type PacketFilterEvent struct {
	PID       uint32
	UID       uint32
	Timestamp time.Time
	Comm      string
	Ret       uint64
}

type rawEventType int32

const (
	rawEventEnter rawEventType = iota
	rawEventExit
)

func loadAttachTracepoints(tp2attach map[string]string, module *bcc.Module) (err error) {
	defer func() {
		// bcc panics when it can't get to something, but we probably want to back off more nicely
		if r := recover(); r != nil {
			var isErr bool
			recovered, isErr := r.(error)
			if isErr {
				err = recovered
			} else {
				err = fmt.Errorf("loadAttachTracepoints recovered a panic: %+v", err)
			}
			return
		}
	}()
	loaded := make(map[string]int)
	for tpName, attachName := range tp2attach {
		tracepoint, exists := loaded[tpName]
		if !exists {
			tracepoint, err = module.LoadTracepoint(tpName)
			if err != nil {
				log.Printf("Unable to load tracepoint %s: %s", tpName, err)
				return
			}
			loaded[tpName] = tracepoint
		}
		err = module.AttachTracepoint(attachName, tracepoint)
		if err != nil {
			log.Printf("Unable to attach tracepoint %s to %s: %s", tpName, attachName, err)
			return
		}
	}
	return nil
}
