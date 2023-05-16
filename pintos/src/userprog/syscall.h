#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "lib/user/syscall.h"
#include "filesys/off_t.h"

void syscall_init (void);

struct file
  {
    struct inode *inode;
    off_t pos;
    bool deny_write;
  };

#endif /* userprog/syscall.h */
