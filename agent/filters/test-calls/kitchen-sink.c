/*
  this file is meant to provide a sequence of predictable syscalls that the 
  bedr agent is supposed to detect.
*/
#include <stdio.h>
#include <unistd.h>

char *const someArgs[] = {"a", "b", "c", '\0'};

void main()
{
  int pid = fork();
  if (pid == 0)
  {
    puts("execve: /bin/true b c");
    execve("/bin/true", someArgs, NULL);
    return;
  }
#ifdef __NR_execveat
  pid = fork();
  if (pid == 0)
  {
    return execveat();
  }
#else
  puts("no execveat :(");
#endif
}