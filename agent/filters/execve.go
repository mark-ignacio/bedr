package filters

import (
	"bytes"
	"context"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/iovisor/gobpf/bcc"
)

// The below filter code is heavily inspired by
// github.com/iovisor/gobpf/blob/master/examples/bcc/execsnoop/execsnoop.go
const execveSource = `
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

enum event_type {
    EVENT_ARG,
    EVENT_RET,
};

struct data_t {
    u64 pid;  // PID as in the userspace term (i.e. task->tgid in kernel)
	u64 ppid; // Parent PID as in the userspace term (i.e task->real_parent->tgid in kernel)
	u64 when;
    char comm[TASK_COMM_LEN];
    enum event_type type;
    char argv[128];
    int retval;
};

struct enter_execve_args {
	u64 __unused__;
	u32 __syscall_nr;
	const char * filename;
	const char *const * argv;
	const char *const * envp;
};

struct exit_execve_args {
	u64 __unused__;
	u32 __syscall_nr;
	u64 ret;
};

BPF_PERF_OUTPUT(events);

static int __submit_arg(struct enter_execve_args *args, void *ptr, struct data_t *data)
{
    bpf_probe_read(data->argv, sizeof(data->argv), ptr);
    events.perf_submit(args, data, sizeof(struct data_t));
    return 1;
}

static int submit_arg(struct enter_execve_args *args, void *ptr, struct data_t *data)
{
    const char *argp = NULL;
    bpf_probe_read(&argp, sizeof(argp), ptr);
    if (argp) {
        return __submit_arg(args, (void *)(argp), data);
    }
    return 0;
}

int trace_sys_enter_execve(struct enter_execve_args *args) {
    struct data_t data = {};
	struct task_struct *task;

    data.pid = bpf_get_current_pid_tgid() >> 32;

    task = (struct task_struct *)bpf_get_current_task();
    // Some kernels, like Ubuntu 4.13.0-generic, return 0
    // as the real_parent->tgid.
    // We use the getPpid function as a fallback in those cases.
    // See https://github.com/iovisor/bcc/issues/1883.
    data.ppid = task->real_parent->tgid;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_ARG;

    __submit_arg(args, (void *)args->filename, &data);

    // skip first arg, as we submitted filename
    #pragma unroll
    for (int i = 1; i < MAX_ARGS; i++) {
        if (submit_arg(args, (void *)&args->argv[i], &data) == 0)
             goto out;
    }

    // handle truncated argument list
    char ellipsis[] = "...";
    __submit_arg(args, (void *)ellipsis, &data);
out:
    return 0;
}

int trace_sys_exit_execve(struct exit_execve_args *args)
{
    struct data_t data = {};
    struct task_struct *task;
	data.when = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    task = (struct task_struct *)bpf_get_current_task();
    // Some kernels, like Ubuntu 4.13.0-generic, return 0
    // as the real_parent->tgid.
    // We use the getPpid function as a fallback in those cases.
    // See https://github.com/iovisor/bcc/issues/1883.
    data.ppid = task->real_parent->tgid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_RET;
    data.retval = args->ret;
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
`

// ExecveEvent is what you get after a completed execve call.
type ExecveEvent struct {
	PPID uint64
	Type int32
	Args []string
	PacketFilterEvent
}

type rawExecveEvent struct {
	Pid    uint64
	Ppid   uint64
	When   uint64
	Comm   [16]byte
	Type   int32
	Argv   [128]byte
	RetVal int32
}

type execveFilter struct {
	attached  bool
	maxArgs   uint64
	module    *bcc.Module
	eventChan chan<- ExecveEvent
	// TODO: prevent leakage for missed execs
	pending map[uint64]*ExecveEvent
}

type rawExecveEventType int32

const (
	execveEventArg rawExecveEventType = iota
	execveEventRet
)

func (e *execveFilter) Listen(ctx context.Context) error {
	e.module = bcc.NewModule(
		strings.Replace(
			execveSource,
			"MAX_ARGS",
			strconv.FormatUint(e.maxArgs, 10), -1,
		),
		[]string{},
	)
	err := loadAttachTracepoints(
		map[string]string{
			"trace_sys_enter_execve": "syscalls:sys_enter_execve",
			"trace_sys_exit_execve":  "syscalls:sys_exit_execve",
		},
		e.module,
	)
	if err != nil {
		return err
	}
	e.attached = true
	table := bcc.NewTable(e.module.TableId("events"), e.module)
	dataChan := make(chan []byte, 100)
	perfMap, err := bcc.InitPerfMap(table, dataChan)
	if err != nil {
		return err
	}
	// auto-close when the context dies
	go func() {
		var eventData []byte
		perfMap.Start()
		defer close(e.eventChan)
		defer perfMap.Stop()
		for {
			select {
			case eventData = <-dataChan:
				err := e.handleData(eventData)
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

func (e *execveFilter) handleData(eventData []byte) error {
	var rawEvent rawExecveEvent
	err := readPerfEvent(eventData, &rawEvent)
	if err != nil {
		return err
	}
	switch rawExecveEventType(rawEvent.Type) {
	case execveEventArg:
		event, exists := e.pending[rawEvent.Pid]
		arg := c2string(rawEvent.Argv[:])
		if !exists {
			event = &ExecveEvent{
				PPID: rawEvent.Ppid,
				PacketFilterEvent: PacketFilterEvent{
					PID:  rawEvent.Pid,
					Comm: c2string(rawEvent.Comm[:]),
				},
			}
			if arg != "" {
				event.Args = []string{arg}
			}
		}
		event.Args = append(event.Args, arg)
		e.pending[rawEvent.Pid] = event
	case execveEventRet:
		event, exists := e.pending[rawEvent.Pid]
		defer delete(e.pending, rawEvent.Pid)
		if !exists {
			log.Printf("Got closing event for unknown PID %d", rawEvent.Pid)
			return nil
		}
		event.Timestamp = time.Unix(0, int64(rawEvent.When)).
			In(time.UTC)
		e.eventChan <- *event
	}
	return nil
}

func (e *execveFilter) Attached() bool {
	return e.attached
}

func (e *execveFilter) Syscalls() []string {
	return []string{"exec"}
}

func c2string(argv []byte) string {
	length := bytes.IndexByte(argv, '\x00')
	if length == -1 {
		return ""
	}
	return string(argv[:length])
}

// NewExecVEFilter creates one.
func NewExecVEFilter(
	eventChan chan<- ExecveEvent,
	maxArgs uint64,
) (PacketFilter, error) {
	if maxArgs == 0 {
		maxArgs = 20
	}
	return &execveFilter{
		eventChan: eventChan,
		maxArgs:   maxArgs,
		pending:   make(map[uint64]*ExecveEvent),
	}, nil
}
