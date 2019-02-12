package filters

import (
	"bytes"
	"context"
	"encoding/binary"
	"math"

	"github.com/iovisor/gobpf/bcc"
)

// SysOpenEvent is the event_t for SysOpen
type SysOpenEvent struct {
	PID      uint32
	TID      uint32
	UID      uint32
	When     uint64
	Filename [255]byte
}

var openAtSource = `
#include <uapi/linux/limits.h>
#include <uapi/linux/ptrace.h>

struct event_t {
	u32 pid;
	u32 tid;
	u32 uid;
	u64 when;
	char filename[255];
	// TODO: flags
};

struct sys_enter_open_args {
    u64 __unused__;
    char *filename;
    u32 flags;
    umode_t mode;cve
};

struct sys_enter_openat_args {
	u64 __unused__;
	u32 syscall_nr;
	u64 dfd;
    char *filename;
    u64 flags;
    u64 mode;
};

BPF_PERF_OUTPUT(events);

int trace_sys_enter_open(struct sys_enter_open_args *args) {
	struct event_t event = {};
	event.when = bpf_ktime_get_ns();
	u64 id = bpf_get_current_pid_tgid();
	event.pid = id >> 32;
	event.tid = id;
	event.uid = bpf_get_current_uid_gid();
	bpf_probe_read_str(&event.filename, sizeof(event.filename), args->filename);
	events.perf_submit(args, &event, sizeof(event));
	return 0;
}

int trace_sys_enter_openat(struct sys_enter_openat_args *args) {
	struct event_t event = {};
	event.when = bpf_ktime_get_ns();
	u64 id = bpf_get_current_pid_tgid();
	event.pid = id >> 32;
	event.tid = id;
	event.uid = bpf_get_current_uid_gid();
	bpf_probe_read_str(&event.filename, sizeof(event.filename), args->filename);
	events.perf_submit(args, &event, sizeof(event));
	bpf_trace_printk("filename: %s\n", event.filename);
	return 0;
}
`

// OpenAtBPF is _
type OpenAtBPF struct {
	Attached bool
	module   *bcc.Module
}

// AttachAndListen returns an optionally buffered channel that contains events.
func (o *OpenAtBPF) AttachAndListen(ctx context.Context, bufferSize int) (<-chan SysOpenEvent, error) {
	openTracepoint, err := o.module.LoadTracepoint("trace_sys_enter_open")
	if err != nil {
		return nil, err
	}
	openAtTracepoint, err := o.module.LoadTracepoint("trace_sys_enter_openat")
	if err != nil {
		return nil, err
	}
	err = o.module.AttachTracepoint("syscalls:sys_enter_open", openTracepoint)
	if err != nil {
		return nil, err
	}
	err = o.module.AttachTracepoint("syscalls:sys_enter_openat", openAtTracepoint)
	if err != nil {
		return nil, err
	}
	o.Attached = true
	data := make(chan []byte, int(math.Max(float64(bufferSize*2), 1)))
	perfMap, err := bcc.InitPerfMap(
		bcc.NewTable(o.module.TableId("events"), o.module),
		data,
	)
	eventChannel := make(chan SysOpenEvent, bufferSize)
	go func() {
		perfMap.Start()
		var eventData []byte
		// TODO: remembering to close three things is bad
		defer close(eventChannel)
		defer o.module.Close()
		defer perfMap.Stop()
		for {
			select {
			case eventData = <-data:
				var event SysOpenEvent
				err = binary.Read(
					bytes.NewBuffer(eventData),
					bcc.GetHostByteOrder(),
					&event,
				)
				data := bytes.TrimRight(event.Filename[:], "\x00")
				if len(data) < 5 {
					continue
				}
				eventChannel <- event
			case <-ctx.Done():
				return
			}
		}
	}()
	return eventChannel, nil
}

// FilenameToString is a handy function.
func FilenameToString(filename [255]byte) string {
	return string(filename[4:])
}

// NewSyscallOpenModule returns a BPF hook for open() + openat()
func NewSyscallOpenModule() *OpenAtBPF {
	return &OpenAtBPF{
		module: bcc.NewModule(openAtSource, []string{}),
	}
}
