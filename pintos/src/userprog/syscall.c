#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/file.h"
static void syscall_handler (struct intr_frame *);
struct file_plus{
    int fd;
    struct file*file;
    struct list_elem elem1;
};
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
    int parameters[10];
    get_parameters(f,parameters,3);
    write(parameters[0],(void *)parameters[1],(unsigned) parameters[2]);
  }
  else if(*(int *)f->esp == SYS_EXIT){
    int parameters[10];
    get_parameters(f,parameters,1);
    exit(parameters[0]);
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
/*打开一份文件，然后返回该文件的fd，如果文件打开失败则返回-1.返回的fd不能是1或0。每一个process都有自己的文件描述符的集合，我的想法是创建一个列表
，里面存放的是一个结构体，包含了文件名和文件fd。 */
int open(const char*file){

}
int read(int fd,void *buffer,unsigned size){
  lock_acquire(&filesystem_lock);
  if(fd == 1 || fd<0){
    lock_release(&filesystem_lock);
    exit(-1);
  }
  else if(fd == 0){
    /* Fd 0 reads from the keyboard using input_getc(). 
    uint8_t input_getc (void) */
    for(int i =0 ;i<size;i++){
      *(uint8_t *)buffer = input_getc();
      buffer++;
    }
    lock_release(&filesystem_lock);
    return size;
  }
  else{
    struct thread *t = thread_current();
    struct list_elem *e;
    if(!list_size(&(t->set_of_file_descriptors))){
      lock_release(&filesystem_lock);
      exit(-1);
    }
    else{
      for(e=list_begin(&(t->set_of_file_descriptors));e!=list_end(&(t->set_of_file_descriptors));e=list_next(&(t->set_of_file_descriptors)))
      {
        struct file_plus *f = list_entry(e,struct file_plus,elem1);
        if(f->fd == fd){
          int len = (int)file_read(f->file,buffer,(off_t)size);
          lock_release(&filesystem_lock);
          return len;
        }
      }
    }
  }
  //NOT_REACHED();
  exit(-1);
}
int write(int fd,const void *buffer, unsigned size)
{
    lock_acquire(&filesystem_lock);
    /* Try writing to fd 0 (stdin),  which may just fail or terminate the process with -1 exit code. */
    if(fd <= 0){
      lock_release(&filesystem_lock);
      exit(-1);
    }
    else if(fd == 1){
       /*write all of buﬀer in one call to putbuf(), */
       putbuf((const char *)buffer,(size_t)size);
       lock_release(&filesystem_lock);
       return size;
    }
    /*根据fd来查找文件名称，通过调用file.c中的函数file_write()来实现写的操作 
    off_t file_write (struct file *file, const void *buffer, off_t size) */
    else{
        struct thread *t = thread_current();
        struct list_elem *e;
        if(!list_size(&(t->set_of_file_descriptors))){
          lock_release(&filesystem_lock);
          exit(-1);
        }
        else{
          for(e=list_begin(&(t->set_of_file_descriptors));e!=list_end(&(t->set_of_file_descriptors));e=list_next(&(t->set_of_file_descriptors)))
          {
            struct file_plus *f = list_entry(e,struct file_plus,elem1);
            if(f->fd == fd){
              int len = (int)file_write(f->file,buffer,(off_t)size);
              lock_release(&filesystem_lock);
              return len;
            }
          }
        }
    }
    exit(-1);
}
void seek(int fd,unsigned position){
  lock_acquire(&filesystem_lock);
  if(fd<=0 || fd==1){
    lock_release(&filesystem_lock);
    exit(-1);
  }
  else{
    struct thread *t = thread_current();
    struct list_elem *e;
    if(!list_size(&(t->set_of_file_descriptors))){
      lock_release(&filesystem_lock);
      exit(-1);
    }
    else{
      for(e=list_begin(&(t->set_of_file_descriptors));e!=list_end(&(t->set_of_file_descriptors));e=list_next(&(t->set_of_file_descriptors)))
      {
        struct file_plus *f = list_entry(e,struct file_plus,elem1);
        if(f->fd == fd){
          file_Seek(f->file,(off_t)position);
          lock_release(&filesystem_lock);
          return;
        }
      }
    }
  }
}
unsigned tell(int fd){
  lock_acquire(&filesystem_lock);
  if(fd<=0 || fd==1){
    lock_release(&filesystem_lock);
    exit(-1);
  }
  else{
    struct thread *t = thread_current();
    struct list_elem *e;
    if(!list_size(&(t->set_of_file_descriptors))){
      lock_release(&filesystem_lock);
      exit(-1);
    }
    else{
      for(e=list_begin(&(t->set_of_file_descriptors));e!=list_end(&(t->set_of_file_descriptors));e=list_next(&(t->set_of_file_descriptors)))
      {
        struct file_plus *f = list_entry(e,struct file_plus,elem1);
        if(f->fd == fd){
          unsigned pos =(unsigned) file_tell(f->file);
          lock_release(&filesystem_lock);
          return pos;
        }
      }
    }
  }
}
void close(int fd){
  lock_acquire(&filesystem_lock);
  if(fd<=0 || fd ==1)
  {
    lock_release(&filesystem_lock);
    exit(-1);
  }
  else{
    struct thread *t =thread_current();
    struct list_elem *e;
    for(e=list_begin(&(t->set_of_file_descriptors));e!=list_end(&(t->set_of_file_descriptors));e=list_next(&(t->set_of_file_descriptors)))
        {
            struct file_plus *f = list_entry(e,struct file_plus,elem1);
            if(f->fd == fd){
                file_close(f->file);
                lock_release(&filesystem_lock);
                return;
            }
        }
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
    tem = (int*)f->esp+i+1;
    is_valid_addr(tem);
    parameters[i] = *(int *)tem;
  }
}