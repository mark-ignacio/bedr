/*
  this file is meant to provide a sequence of predictable syscalls that the 
  bedr agent is supposed to detect.
*/
#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>

char *const someArgs[] = {"a", "b", "c", '\0'};


void main()
{
  // execve
  int pid;
  int _status;
  pid = fork();
  if (pid == 0)
  {
    puts("execve: /bin/true b c");
    execve("/bin/true", someArgs, NULL);
    return;
  }
  wait(&_status);
#ifdef __NR_execveat
  pid = fork();
  if (pid == 0)
  {
    return execveat();
  }
#else
  puts("no execveat :(");
#endif
  // open(at)
  int fd, dirfd;
  puts("open: /proc/cpuinfo O_RDONLY");
  fd = open("/proc/cpuinfo", O_RDONLY);
  close(fd);
  dirfd = open("/proc", __O_PATH);
  fd = openat(dirfd, "/proc/cpuinfo", O_RDONLY);
  close(fd);
  close(dirfd);
}