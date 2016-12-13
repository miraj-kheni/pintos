#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "filesys/file.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
  
static void syscall_handler (struct intr_frame *);
int vaddr_to_kvaddr(const void *vaddr);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

int vaddr_to_kvaddr(const void *vaddr) {
  return (int)pagedir_get_page(thread_current()->pagedir, vaddr);
}

void sys_exit(int exit_code)
{
  printf("%s: exit(%d)\n", thread_current()->name, exit_code);
  process_table[thread_current()->tid]->exit_status = exit_code;
  process_table[thread_current()->tid]->running = false;
  sema_up(process_table[thread_current()->tid]->wait_sema);
  thread_exit();
}

int sys_write(int fd, const void *buffer, unsigned size, int *nbytes_written)
{
  if (fd == STDOUT_FILENO) {
    putbuf((char *)buffer, (size_t)size);
    *nbytes_written = size;
    return 0;
  }
/*  struct file_descriptor *fdesc = thread_current()->file_table[fd];
  if(fdesc == NULL) {
    return -1; 
  }
  lock_acquire(fdesc->fdlock);
  *nbytes_written = file_write(fdesc->f, buffer, size);
  lock_release(fdesc->fdlock);*/
  return 0;
}

static void
syscall_handler (struct intr_frame *f) 
{
  //printf ("system call!\n");
  //thread_exit ();

  int SYSCALL_NUM = *(int *)f->esp;
  int ret_code = -1;
  int ret_val = 0;

  switch(SYSCALL_NUM) {
    case SYS_HALT:
      shutdown_power_off();
      break;
    case SYS_EXIT:
      sys_exit(*((int *)f->esp + 1));
      break;
    case SYS_WRITE:
      ret_code = sys_write(*(int *)(f->esp + 4), (const void *)*(char **)(f->esp + 8), *(unsigned *)(f->esp+ 12), &ret_val);
      if(ret_code == -1) {
        sys_exit(-1);
      }
      f->eax = ret_val; 
      break;
/*    case SYS_READ:
       int fd = *((int *)f->esp + 1);
       char *buffer = *(char **)(f->esp + 2);
       unsigned nbytes = *((unsigned *)(f->esp) + 3);
       int nbytes_written = 0;
       ret_code = sys_read(fd, buffer, nbytes, &nbytes_written);
       f->eax = nbytes_written;
       break;
*/
  } 
}
