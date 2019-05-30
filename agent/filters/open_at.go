package filters

import (
	"context"
	"log"

	"github.com/iovisor/gobpf/bcc"
	"golang.org/x/sys/unix"
)

var openAtSource = `
#include <uapi/linux/limits.h>
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fdtable.h>
#include <linux/dcache.h>` + fd2PathSource + `

enum event_type {
	EVENT_ENTER,
	EVENT_EXIT,
};

struct event_t {
	u32 syscall_nr;
	u32 pid;
	u32 tid;
	u32 uid;
	u64 when;
	u64 flags;
	u64 ret;
	enum event_type type;
    char comm[16];
	char filename[255];
};

struct sys_enter_open_args {
    u64 __unused__;
	u32 syscall_nr;
    const char * filename;
    u64 flags;
    umode_t mode;
};

struct sys_enter_openat_args {
	u64 __unused__;
	u32 syscall_nr;
	u64 dfd;
    const char * filename;
    u64 flags;
    umode_t mode;
};

struct sys_exit_open_args {
	u64 __unused__;
	u32 syscall_nr;
	u64 ret;
};


BPF_PERF_OUTPUT(events);

int trace_sys_enter_open(struct sys_enter_open_args *args) {
	struct event_t event = {
		.syscall_nr = args->syscall_nr,
		.type = EVENT_ENTER,
		.when = bpf_ktime_get_ns(),
	};
	u64 id = bpf_get_current_pid_tgid();
	event.pid = id;
	event.tid = id << 32;
	event.uid = bpf_get_current_uid_gid();
	event.flags = args->flags;
	bpf_get_current_comm(&event.comm, sizeof(event.comm));
	bpf_probe_read(&event.filename, sizeof(event.filename), args->filename);
	events.perf_submit(args, &event, sizeof(event));
	return 0;
}

int trace_sys_enter_openat(struct sys_enter_openat_args *args) {
	struct event_t event = {
		.syscall_nr = args->syscall_nr,
		.type = EVENT_ENTER,
		.when = bpf_ktime_get_ns(),
	};
	u64 id = bpf_get_current_pid_tgid();
	event.pid = id;
	event.tid = id << 32;
	event.uid = bpf_get_current_uid_gid();
	bpf_get_current_comm(&event.comm, sizeof(event.comm));
	bpf_probe_read(&event.filename, sizeof(event.filename), args->filename);
	event.flags = args->flags;
	events.perf_submit(args, &event, sizeof(event));
	return 0;
}

// got lucky - ret sigs are the same
int trace_sys_exit_open(struct sys_exit_open_args *args) {
	struct event_t event = {};
	event.syscall_nr = args->syscall_nr;
	event.type = EVENT_EXIT;
	event.when = bpf_ktime_get_ns();
	u64 id = bpf_get_current_pid_tgid();
	event.pid = id;
	event.tid = id << 32;
	event.ret = args->ret;
	events.perf_submit(args, &event, sizeof(event));
	return 0;
}

int trace_sys_exit_openat(struct sys_exit_open_args *args) {
	struct event_t event = {};
	event.syscall_nr = args->syscall_nr;
	event.type = EVENT_EXIT;
	event.when = bpf_ktime_get_ns();
	u64 id = bpf_get_current_pid_tgid();
	event.pid = id;
	event.tid = id << 32;
	event.ret = args->ret;
	events.perf_submit(args, &event, sizeof(event));
	return 0;
}
`

// OpenEvent is what you get after a completed open(at) call.
type OpenEvent struct {
	Filename string
	Flags    int
	IsAt     bool
	PacketFilterEvent
}

type rawOpenEvent struct {
	Syscall  uint32
	PID      uint32
	TID      uint32
	UID      uint32
	When     int64
	Flags    uint64
	Ret      uint64
	Type     rawEventType
	Comm     [16]byte
	Filename [255]byte
}

type openFilter struct {
	attached  bool
	module    *bcc.Module
	eventChan chan<- OpenEvent
	// TODO: prevent leakage
	pending map[uint32]map[uint32]*OpenEvent
}

func (o *openFilter) Listen(ctx context.Context) error {
	o.module = bcc.NewModule(openAtSource, []string{})
	dataChan, perfMap, err := genericListen(
		o.module,
		map[string]string{
			"trace_sys_enter_open":   "syscalls:sys_enter_open",
			"trace_sys_exit_open":    "syscalls:sys_exit_open",
			"trace_sys_enter_openat": "syscalls:sys_enter_openat",
			"trace_sys_exit_openat":  "syscalls:sys_exit_openat",
		},
		"events",
	)
	if err != nil {
		return err
	}
	o.attached = true
	go func() {
		var eventData []byte
		perfMap.Start()
		defer close(o.eventChan)
		defer perfMap.Stop()
		for {
			select {
			case eventData = <-dataChan:
				err := o.handleData(eventData)
				if err != nil {
					log.Panicf("error decoding event - %s", err)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	return nil
}

func (o *openFilter) handleData(eventData []byte) error {
	var raw rawOpenEvent
	err := readPerfEvent(eventData, &raw)
	if err != nil {
		return err
	}
	pidFiles := o.pending[raw.PID]
	switch rawEventType(raw.Type) {
	case rawEventEnter:
		if pidFiles == nil {
			pidFiles = make(map[uint32]*OpenEvent)
		}
		pidFiles[raw.TID] = &OpenEvent{
			Filename: c2string(raw.Filename[:]),
			Flags:    int(raw.Flags >> 10),
			IsAt:     raw.Syscall == unix.SYS_OPENAT,
			PacketFilterEvent: PacketFilterEvent{
				PID:       raw.PID,
				UID:       raw.UID,
				Timestamp: ktime2Time(raw.When),
				Comm:      c2string(raw.Comm[:]),
			},
		}
		o.pending[raw.PID] = pidFiles
	case rawEventExit:
		if pidFiles == nil || pidFiles[raw.TID] == nil {
			log.Printf("warning: exiting a open/at() that we didn't enter")
			break
		}
		if len(pidFiles) == 1 {
			defer delete(o.pending, raw.PID)
		}
		event := pidFiles[raw.TID]
		event.Ret = raw.Ret
		o.eventChan <- *event
	}
	return nil
}

func (o *openFilter) Attached() bool {
	return o.attached
}

func (o *openFilter) Syscalls() []string {
	return []string{"open", "openat"}
}

// TODO: func (o *openFilter) PIDExit()

// NewOpenFilter creates one.
func NewOpenFilter(eventChan chan<- OpenEvent) (PacketFilter, error) {
	return &openFilter{
		eventChan: eventChan,
		pending:   make(map[uint32]map[uint32]*OpenEvent),
	}, nil
}
