# Hijacking System Calls and Monitoring Processes

#### Assignment from CSC369 at the University of Toronto

Hijack (intercepting) system calls by writing and installing a very basic kernel module to the Linux kernel.

"Hijacking (intercepting) a system call" means. Implemented a new system call named my_syscall, which will allows to send commands from user-space, to intercept another pre-existing system call (like read, write, open, etc.). After a system call is intercepted, the intercepted system call would log a message first before continuing performing what it was supposed to do.

##### run on your own risk, this code modify your kernel and might damage your system
