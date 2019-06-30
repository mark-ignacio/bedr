package filters

import (
	"context"
	"net"

	"github.com/iovisor/gobpf/bcc"
)

const connectSource = `
#include <sys/socket.h>
#include <sys/types.h>

enum event_type {
	EVENT_ENTER,
	EVENT_EXIT,
};

struct event_t {
	u32 pid;
	u32 tid;
	u32 uid;
	u64 when;
	u64 ret;
	enum event_type type;
	u32 sa_family;
	char sa_data[16];
};

struct sys_enter_connect_args {
	u64 __unused__;
	u32 syscall_nr;
	u64 fd;
	struct sockaddr *uservaddr;
	u64 addrlen;
};

BPF_PERF_OUTPUT(events);

int trace_sys_enter_connect(struct sys_enter_connect_args *args) {
	u64 id = bpf_get_current_pid_tgid();
	struct event_t event = {
		.when = bpf_ktime_get_ns(),
		.pid = id,
		.tid = id << 32,
		.uid = bpf_get_current_uid_gid(),
		.type = EVENT_ENTER,
	};
}
`

// ConnectEvent describes a socket connection initiation
type ConnectEvent struct {
	SockFD   int
	Address  net.Addr
	Port     string
	Protocol string
}

type connectFilter struct {
	attached  bool
	module    *bcc.Module
	eventChan chan<- ConnectEvent
}

func (c *connectFilter) Listen(ctx context.Context) error {
	c.module = bcc.NewModule(connectSource, []string{})
	return nil
}

func (c connectFilter) Attached() bool {
	return c.attached
}

// NewConnectFilter creates one.
func NewConnectFilter(eventChan chan<- ConnectEvent) (PacketFilter, error) {
	return &connectFilter{
		eventChan: eventChan,
	}, nil
}
