# bedr

an experimental, BPF-powered Linux EDR. Ships syscall info into a TCP socket for central collection and data crunching.

In order to work on machines with the future, read-only [kernel_lockdown](https://lwn.net/Articles/751561/) mode enabled, kprobes are forbidden for features that hope for wide adoption.

## syscall coverage

based on: [/arch/x86/entry/syscalls/syscall_64.tbl](https://github.com/torvalds/linux/blob/9c8ad7a2ff0bfe58f019ec0abc1fb965114dde7d/arch/x86/entry/syscalls/syscall_64.tbl)


| syscall  | status |
|----------|--------|
| open     | ✔️      |
| openat   | ✔️      |
| execve   | ✔️      |
| execveat | ❌      |
| connect  | ❌      |
| bind     | ❌      |


## Usage

### Requirements

* For building, Go 1.11+ because of go modules
* [Linux kernel 4.7+](https://github.com/iovisor/bcc/blob/8835de693babc7c8c039209dab914c11d2182d24/docs/kernel-versions.md) for kernel tracepoint support
* [kernel lockdown mode](https://lwn.net/Articles/751561/) disabled
* `bcc` (Debian) or `bcc-devel` (Fedora) for JIT filter compliation.

### Starting the thing

```
bedr/agent $ sudo -E go run main.go
```

If not a real service, `Ctrl+C` or pkill it.

## About the license

This repo is covered under GNU AGPLv3 so it's harder for bad-natured folk to make security vendor money directly off anything inside of this repository.

Feel free to ~~fight~~ ask me about separately licensing it.