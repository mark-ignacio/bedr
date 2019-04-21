# bedr

an experimental, BPF-powered Linux EDR. Ships syscall info into a TCP socket for central collection and data crunching.

In order to work on machines with [kernel_lockdown](https://lwn.net/Articles/735564/) enabled, kprobes are forbidden for features that hope for wide adoption.

## syscall coverage

based on: https://github.com/torvalds/linux/blob/master/arch/x86/entry/syscalls/syscall_64.tbl


| syscall  | status |
|----------|--------|
| open     | ❌      |
| openat   | ❌      |
| execve   | ✔️      |
| execveat | ❌      |
| connect  | ❌      |
| bind     | ❌      |


## Usage

### Requirements

* For building, Go 1.11+ because of go modules
* [Linux kernel 4.7+](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md) for kernel tracepoint support
* `bcc` (Debian) or `bcc-devel` (Fedora) for JIT filter compliation.

### Starting the thing

```
bedr/agent $ sudo -E go run main.go
```

If not a real service, `Ctrl+C` or pkill it.

## About the license

This repo is covered under GNU AGPLv3 so it's harder for bad-natured folk to make security vendor money directly off anything inside of this repository.

Feel free to ~~fight~~ ask me about separately licensing it.