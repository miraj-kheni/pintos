#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>

void syscall_init (void);

int sys_wait(int pid);
int sys_exec(const char *cmd_name);
void sys_exit(int exit_code);
int sys_write(int fd, const void *buffer, unsigned size, int *nbytes_written);
int sys_read(int fd, void *buffer, unsigned size, int *nbytes_read);
bool sys_create(const char *filename, unsigned initial_size);
bool sys_remove(const char *filename);
int sys_open(const char *filename);
void sys_close(int fd);
int sys_filesize(int fd);
unsigned sys_tell(int fd);
void sys_seek(int fd, unsigned position);
#endif /* userprog/syscall.h */
