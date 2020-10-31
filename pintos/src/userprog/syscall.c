#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
static void syscall_handler (struct intr_frame *);
struct lock filesystem_lock;
void
syscall_init (void) 
{
  lock_init(&filesystem_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  is_valid_addr(f->esp);
  if(*(int *)f->esp == SYS_WRITE){
    int *parameters;
    get_parameters(f,parameters,3);
    write(parameters[0],parameters[1],parameters[2]);
  }
}
void
is_valid_addr (const void *addr)
{
  if (addr == NULL || !is_user_vaddr (addr) || pagedir_get_page (thread_current ()->pagedir, addr) == NULL)
    {
      if (lock_held_by_current_thread (&filesystem_lock))
        lock_release (&filesystem_lock);
      exit (-1);
    }
}
void
is_valid_buffer (void *buffer, unsigned size)
{
  char *temp = (char *)buffer;
  is_valid_addr ((const char *)temp);
  temp+=size;
  is_valid_addr ((const char *)temp);
}
int write(int fd,const void *buffer, unsigned size)
{
    lock_acquire(&filesystem_lock);
    /* Try writing to fd 0 (stdin),  which may just fail or terminate the process with -1 exit code. */
    if(fd == 0){
      lock_release(&filesystem_lock);
      exit(-1);
    }
    if(fd == 1){
       /*write all of buﬀer in one call to putbuf(), */
       putbuf((const char *)buffer,(size_t)size);
       lock_release(&filesystem_lock);
       return size;
    }
}
int exit(int stauts){
  struct thread* t = thread_current();
  t->ret = stauts;
  thread_exit();
}
/*获取压到栈上的系统调用的参数
第一个参数为中断栈帧，第二个参数为存放系统调用的参数(不能使用void*)，第三个参数为该系统调用有几个参数*/
void get_parameters(struct intr_frame *f,int *parameters,int len)
{
  void *tem;
  for(int i=0;i<len;i++){
    tem = f->esp+i+1;
    is_valid_addr(tem);
    parameters[i] = (*(int*)tem);
  }
}