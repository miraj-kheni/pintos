#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

void sys_exit(int exit_code);
int sys_write(int fd, const void *buffer, unsigned size, int *nbytes_written);
#endif /* userprog/syscall.h */
