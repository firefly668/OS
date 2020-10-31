#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"

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
  printf ("system call!\n");
  thread_exit ();
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