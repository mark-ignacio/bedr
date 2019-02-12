package filters

import (
	"context"
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
	// Syscalls returns what syscalls this filter covers, which is also a guide to what events are available from the channel.
	Syscalls() []string
}

// PacketFilterEvent is (generally) what all BPF event structs should embed, for interop's sake.
type PacketFilterEvent struct {
	PID       uint64
	Timestamp time.Time
	Comm      string
}

func loadAttachTracepoints(tp2attach map[string]string, module *bcc.Module) error {
	var err error
	loaded := make(map[string]int)
	for tpName, attachName := range tp2attach {
		tracepoint, exists := loaded[tpName]
		if !exists {
			tracepoint, err = module.LoadTracepoint(tpName)
			if err != nil {
				log.Printf("Unable to load tracepoint %s: %s", tpName, err)
				return err
			}
			loaded[tpName] = tracepoint
		}
		err = module.AttachTracepoint(attachName, tracepoint)
		if err != nil {
			log.Printf("Unable to attach tracepoint %s to %s: %s", tpName, attachName, err)
			return err
		}
	}
	return nil
}
