#include <inttypes.h>
#include <stdio.h>
#include <syscall-nr.h>
#include "userprog/syscall.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
  
static void syscall_handler (struct intr_frame *);
static int vaddr_to_kvaddr(const void *vaddr);
static bool is_valid_buffer(const void *vaddr, unsigned size);

static int
vaddr_to_kvaddr(const void *vaddr)
{
  return (int)pagedir_get_page(thread_current()->pagedir, vaddr);
}

static bool
is_valid_buffer(const void *vaddr, unsigned size)
{
  void *temp_buffer = vaddr;
  for(unsigned i = 0; i < size; i++) {
    if(!(vaddr < PHYS_BASE) || vaddr < 0x08048000 || pagedir_get_page(thread_current()->pagedir, vaddr) == NULL)
    {
      return false;
    }
    temp_buffer++;
  }
  return true;
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

int
sys_exec(const char *cmd_name)
{
  return process_execute(cmd_name);  
}

int
sys_wait(int pid)
{
  if(pid < 0 || pid >= MAX_PROC) {
    sys_exit(-1);
  }
  return process_wait(pid);
}

void
sys_exit(int exit_code)
{

  for(int i = 2; i < MAX_FILE; i++) {
    if(thread_current()->file_table[i] != NULL) {
      file_close(thread_current()->file_table[i]);
      thread_current()->file_table[i] = NULL;
    }
  }
  file_close(thread_current()->executable);
  /*for(int i=1; i < MAX_PROC; i++) {
    if(process_table[i] != NULL && process_table[i]->parent_tid == thread_current()->tid) {
      if(!process_table[i]->running) {
        printf("destroying %d\n",i);
        destroy_process_desc(i);
        process_table[i] = NULL;
      }
    } 
  }*/
  printf("%s: exit(%d)\n", thread_current()->name, exit_code);
  process_table[thread_current()->tid]->exit_status = exit_code;
  process_table[thread_current()->tid]->running = false;
  sema_up(process_table[thread_current()->tid]->wait_sema);
  thread_exit();
}

int
sys_write(int fd, const void *buffer, unsigned size, int *nbytes_written)
{
  if(fd < 0 || fd > MAX_FILE) {
    return -1;
  }

  if (fd == STDOUT_FILENO) {
    putbuf((char *)buffer, (size_t)size);
    *nbytes_written = size;
    return 0;
  }
  struct file *f = thread_current()->file_table[fd];
  if(f == NULL) {
    return -1; 
  }
  *nbytes_written = file_write(f, buffer, size);
  return 0;
}

int
sys_read(int fd, void *buffer, unsigned size, int *nbytes_read)
{
  if(fd < 0 || fd > MAX_FILE) {
    return -1;
  }
  struct file *f = thread_current()->file_table[fd];
  if(f == NULL) {
    return -1; 
  }
  *nbytes_read = file_read(f, buffer, size);
  return 0;
}

bool sys_create(const char *filename, unsigned initial_size)
{
  return filesys_create(filename, initial_size);
}

bool sys_remove(const char *filename)
{
  return filesys_remove(filename);
}

int
sys_filesize(int fd)
{
  if(fd < 0 || fd > MAX_FILE) {
    return -1;
  }
  if(thread_current()->file_table[fd] == NULL) {
    return -1;
  }
  return file_length(thread_current()->file_table[fd]);
}

unsigned
sys_tell(int fd)
{
  if(fd < 0 || fd > MAX_FILE) {
    return -1;
  }
  if(thread_current()->file_table[fd] == NULL) {
    return -1;
  }
  return file_tell(thread_current()->file_table[fd]);
}

int
sys_open(const char *filename)
{
  struct file *f = filesys_open(filename);
  if(f == NULL) {
    return -1;
  }
  for(int i = 2; i < MAX_FILE; i++) {
    if(thread_current()->file_table[i] == NULL) {
      thread_current()->file_table[i] = f;
      return i;
    }
  }
  return -1;
}

void
sys_close(int fd)
{
  if(fd < 0 || fd > MAX_FILE) {
    return;
  }
  if(thread_current()->file_table[fd] != NULL) {
    file_close(thread_current()->file_table[fd]);
    thread_current()->file_table[fd] = NULL;
  }
}

void
sys_seek(int fd, unsigned position)
{
  if(fd < 0 || fd > MAX_FILE) {
    return;
  }
  if(thread_current()->file_table[fd] != NULL) {
    file_seek(thread_current()->file_table[fd], position);
  }
}

static void
syscall_handler (struct intr_frame *f) 
{
  //printf ("system call!\n");
  //thread_exit ();

  if(!is_valid_buffer((const void *)f->esp,1)) {
    sys_exit(-1);
  }

  int SYSCALL_NUM = *(int *)f->esp;
  int ret_code = -1;
  int ret_val = 0;

  switch(*(int *)f->esp) {
    case SYS_HALT:
      shutdown_power_off();
      break;
    case SYS_EXIT:
      if(!is_valid_buffer((const void *)(f->esp + 4),1)) {
        sys_exit(-1);
      }
      sys_exit(*(int *)(f->esp + 4));
      break;
    case SYS_WRITE:
      if(!is_valid_buffer((const void *)*(char **)(f->esp + 8), *(unsigned *)(f->esp + 12))) {
        sys_exit(-1); 
      }
      ret_code = sys_write(*(int *)(f->esp + 4), (const void *)*(char **)(f->esp + 8), *(unsigned *)(f->esp+ 12), &ret_val);
      if(ret_code == -1) {
        sys_exit(-1);
      }
      f->eax = ret_val; 
      break;
    case SYS_READ:
      if(!is_valid_buffer((void *)*(char **)(f->esp + 8), *(unsigned *)(f->esp + 12))) {
        sys_exit(-1); 
      }
      ret_code = sys_read(*(int *)(f->esp + 4), *(char **)(f->esp + 8), *(unsigned *)(f->esp+ 12), &ret_val);
      if(ret_code == -1) {
        sys_exit(-1);
      }
      f->eax = ret_val;
      break;
    case SYS_OPEN:
      if(!is_valid_buffer((const char *)*(char **)(f->esp + 4),1)) {
        sys_exit(-1);
      }
      ret_code = sys_open((const char *)*(char **)(f->esp + 4));
      f->eax = ret_code;
      break;
    case SYS_CLOSE:
      sys_close(*(int *)(f->esp + 4));
      break;
    case SYS_CREATE:
      if(!is_valid_buffer((const char *)*(char **)(f->esp + 4),1)) {
        sys_exit(-1);
      }
      ret_code = sys_create((const char *)*(char **)(f->esp + 4), *(unsigned *)(f->esp + 8));
      f->eax = ret_code;
      break;
    case SYS_REMOVE:
      if(!is_valid_buffer((const char *)*(char **)(f->esp + 4),1)) {
        sys_exit(-1);
      }
      ret_code = sys_remove((const char *)*(char **)(f->esp + 4));
      f->eax = ret_code;
      break;
    case SYS_FILESIZE:
      ret_code = sys_filesize(*(int *)(f->esp + 4));
      f->eax = ret_code;
      break;
    case SYS_TELL:
      ret_code = sys_tell(*(int *)(f->esp + 4));
      f->eax = ret_code;
      break;
    case SYS_SEEK:
      sys_seek(*(int *)(f->esp + 4), *(unsigned *)(f->esp + 8));
      break;
    case SYS_EXEC:
      if(!is_valid_buffer((const char *)*(char **)(f->esp + 4),1)) {
        sys_exit(-1);
      }
      ret_code = sys_exec((const char *)vaddr_to_kvaddr(*(char **)(f->esp + 4)));
      f->eax = ret_code;
      break;
    case SYS_WAIT:
      ret_code = sys_wait(*(int *)(f->esp + 4));
      f->eax = ret_code;
      break;
    default:
      sys_exit(-1); 
  } 
}
