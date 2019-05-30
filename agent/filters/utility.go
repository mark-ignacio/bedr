package filters

import (
	"bytes"
	"encoding/binary"
	"syscall"
	"time"
	"unsafe"

	"github.com/iovisor/gobpf/bcc"
	"golang.org/x/sys/unix"
)

var ktimeOffsetNS int64

// TODO: delete when this is real - https://github.com/iovisor/bcc/issues/237
// n.b. you must `#include <linux/sched.h>` + `#include <linux/fdtable.h>` for this to work.
const fd2PathSource = `
static void fd2path(u64 fd, char ** path) {
	struct task_struct *curr = (struct task_struct *)bpf_get_current_task();
	// dive dive dive
    struct files_struct *files = NULL;
    bpf_probe_read(&files, sizeof(files), &curr->files);
	struct fdtable *fdt = NULL;
    bpf_probe_read(&fdt, sizeof(fdt), &files->fdt);
	struct file **_fd = NULL;
    bpf_probe_read(&_fd, sizeof(_fd), &fdt->fd);
    struct file *f = NULL;
	bpf_probe_read(&f, sizeof(f), &_fd[fd]);
    struct dentry *de = NULL;
    bpf_probe_read(&de, sizeof(de), &f->f_path.dentry);
    struct qstr qs = {};
	bpf_probe_read(&qs, sizeof(qs), (void*)&de->d_name);
	bpf_probe_read(path, sizeof(path), qs.name);
}
`

// attaches tracepoints, creates a perfMap, and creates a data channel. or dies trying
func genericListen(
	module *bcc.Module, toAttach map[string]string, tableName string,
) (
	<-chan []byte,
	*bcc.PerfMap,
	error,
) {
	err := loadAttachTracepoints(toAttach, module)
	if err != nil {
		return nil, nil, err
	}
	table := bcc.NewTable(module.TableId(tableName), module)
	dataChan := make(chan []byte, 100)
	perfMap, err := bcc.InitPerfMap(table, dataChan)
	if err != nil {
		close(dataChan)
	}
	return dataChan, perfMap, err
}

// generically converts null-terminated byte arrays to strings
func c2string(argv []byte) string {
	length := bytes.IndexByte(argv, '\x00')
	if length == -1 {
		return ""
	}
	return string(argv[:length])
}

// gives you an off-by-nanoseconds time to satiate humans
func ktime2Time(ktimeNS int64) time.Time {
	return time.Unix(0, ktimeNS+ktimeOffsetNS)
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
		unix.CLOCK_MONOTONIC, /* CLOCK_MONOTONIC */
		uintptr(unsafe.Pointer(&timespec)),
		0,
	)
	ktimeOffsetNS = time.Now().UnixNano() - syscall.TimespecToNsec(timespec)
}
