package filters

import (
	"context"
	"log"
	"net"
	"syscall"

	"github.com/iovisor/gobpf/bcc"
)

const connectSource = `
#include <net/sock.h>
#include <linux/sched.h>

struct event_t {
	u32 pid;
	u32 uid;
	u64 when;
	char comm[TASK_COMM_LEN];
	u16 family;
	u16 dport;
	char daddr[16];
};

struct sys_enter_connect_args {
	u64 __unused__;
	u32 syscall_nr;
	u64 fd;
	struct sockaddr *uservaddr;
	u64 addrlen;
};

struct sys_exit_connect_args {
	u64 __unused__;
	u32 syscall_nr;
	u64 ret;
};

BPF_HASH(socks, u32, struct sockaddr *);
BPF_PERF_OUTPUT(events);

int trace_sys_enter_connect(struct sys_enter_connect_args *args) {
	u32 tid = bpf_get_current_pid_tgid();
	struct sockaddr* addr = args->uservaddr;
	socks.update(&tid, &addr);
	return 0;
}

int trace_sys_exit_connect(struct sys_exit_connect_args *args) {
	u64 uid_gid = bpf_get_current_uid_gid();
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 uid = uid_gid;
	u32 pid = pid_tgid >> 32;
	u32 tid = pid_tgid;
	// only emit if it worked?
	struct sockaddr **psock;
	psock = socks.lookup(&tid);
	if (psock == 0) {
		return 0;
	}
	if (args->ret != 0) {
		socks.delete(&tid);
		return 0;
	}
    struct event_t event = {};
	event.pid = pid;
	event.uid = uid;
	event.when = bpf_ktime_get_ns();
	bpf_get_current_comm(&event.comm, sizeof(event.comm));
	bpf_probe_read(&event.family, sizeof(event.family), &(*psock)->sa_family);
	if (event.family == AF_INET) {
		struct sockaddr_in sock4;
		bpf_probe_read(&sock4, sizeof(sock4), *psock);
		event.dport = ntohs(sock4.sin_port);
		bpf_probe_read(&event.daddr, sizeof(event.daddr), &sock4.sin_addr.s_addr); 
		events.perf_submit(args, &event, sizeof(event));
	} else if (event.family == AF_INET6) {
		struct sockaddr_in6 sock6;
		bpf_probe_read(&sock6, sizeof(sock6), *psock);
		event.dport = ntohs(sock6.sin6_port);
		bpf_probe_read(&event.daddr, sizeof(event.daddr), &sock6.sin6_addr.s6_addr);
		events.perf_submit(args, &event, sizeof(event));
	}
	socks.delete(&tid);
	return 0;
}
`

// ConnectEvent describes a socket connection initiation
type ConnectEvent struct {
	PacketFilterEvent
	IP   net.IP
	Port uint16
}

type rawConnectEvent struct {
	PID    uint32
	UID    uint32
	When   uint64
	Comm   [16]byte
	Family uint16
	DPort  uint16
	DAddr  [16]byte
}

type connectFilter struct {
	attached  bool
	module    *bcc.Module
	eventChan chan<- ConnectEvent
}

func (c *connectFilter) Listen(ctx context.Context) error {
	c.module = bcc.NewModule(connectSource, []string{})
	dataChan, perfMap, err := genericListen(
		c.module,
		map[string]string{
			"trace_sys_enter_connect": "syscalls:sys_enter_connect",
			"trace_sys_exit_connect":  "syscalls:sys_exit_connect",
		},
		"events",
	)
	if err != nil {
		return err
	}
	go func() {
		var eventData []byte
		perfMap.Start()
		defer close(c.eventChan)
		defer perfMap.Stop()
		for {
			select {
			case eventData = <-dataChan:
				err := c.handleData(eventData)
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
func (c *connectFilter) handleData(eventData []byte) error {
	var raw rawConnectEvent
	err := readPerfEvent(eventData, &raw)
	if err != nil {
		return err
	}
	var ip net.IP
	switch raw.Family {
	case syscall.AF_INET:
		ip = net.IP(raw.DAddr[:][:4])
	case syscall.AF_INET6:
		ip = net.IP(raw.DAddr[:])
	default:
		log.Panicf("unhandled sa_family %d", raw.Family)
	}
	event := ConnectEvent{
		PacketFilterEvent: PacketFilterEvent{
			PID:       raw.PID,
			UID:       raw.UID,
			Timestamp: ktime2Time(int64(raw.When)),
			Comm:      c2string(raw.Comm[:]),
		},
		IP:   ip,
		Port: raw.DPort,
	}
	c.eventChan <- event
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
