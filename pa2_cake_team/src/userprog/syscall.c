#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "devices/shutdown.h"
#include "threads/synch.h"

static void syscall_handler(struct intr_frame *);
/*Syscalls related to processes*/
void halt(void);
void exit(int status) NO_RETURN;
pid_t exec(const char *file);
int wait(pid_t pid);
/*Syscalls related to files*/
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file); /*TODO*/
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);        /*TODO*/
int write(int fd, const void *buffer, unsigned size); /*TODO*/
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd); /*TODO*/
/*Student Helper Functions: */
bool is_memory_safe(void *stack_ptr);
bool validate_args(void *stack_ptr, int arg_no);
struct file *get_file(int fd);
bool is_valid_fd(int fd);

struct lock exec_lock;

void syscall_init(void)
{
  lock_init(&exec_lock);
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* Safe Memory Access */
bool is_memory_safe(void *stack_ptr)
{
  if (stack_ptr >= PHYS_BASE || stack_ptr == NULL)
  {
    return false;
  }
  uint64_t *mapped = pagedir_get_page(thread_current()->pagedir, stack_ptr);
  if (mapped == NULL)
  {
    return false;
  }
  return true;
}

/*takes in a file descriptor (fd) and returns the associated file*/
struct file *get_file(int fd)
{
  int idx = fd - 2;
  struct list_elem *file_e = list_access(&thread_current()->file_list, idx);
  struct file *file = list_entry(file_e, struct file, file_elem);
  return file;
}

/*Makes sure fd is within the bounds of our file_list in thread_current*/
bool is_valid_fd(int fd)
{
  return fd < thread_current()->next_fd;
}

/* Validates that all agruments of
  a syscall are memory safe */
bool validate_args(void *stack_ptr, int arg_no)
{
  int i = 1;
  while (i <= arg_no)
  {
    if (!is_memory_safe(stack_ptr + (i * 4)))
      return false;
    i += 1;
  }
  return true;
}

int read(int fd, void *buffer, unsigned size)
{
  if (fd == 0)
  {
    input_getc();
    return size;
  }
  else if (fd == 1)
  {
    // Does nothing because you can't read from STDOUT
    return size;
  }
  else
  {
    struct file *file = get_file(fd);
    return file_read(file, buffer, size);
  }
}

/*Student Code: Write syscall*/
int write(int fd, const void *buffer, unsigned size)
{
  if (is_user_vaddr(&buffer))
  {
    return size;
  }
  if (fd == 0)
  {
    // Does nothing because you can't write to stdin
    return size;
  }
  else if (fd == 1)
  {
    putbuf(buffer, size);
    return size;
  }
  else
  {
    struct file *file = get_file(fd);
    return file_write(file, buffer, size);
  }
}
int open(const char *file)
{
  if (file == NULL)
  {
    return -1;
  }
  struct file *ret_file;
  ret_file = filesys_open(file);
  int fd; /*the file descriptor we are returning*/
  if (ret_file == NULL)
  {
    // unsuccessful open
    return -1;
  }
  else
  {
    fd = thread_current()->next_fd;
    thread_current()->next_fd += 1;
    list_push_back(&thread_current()->file_list, &ret_file->file_elem);
    return fd;
  }
}

bool create(const char *file, unsigned initial_size)
{
  if (file == NULL)
  {
    return false;
  }
  return filesys_create(file, initial_size);
}

void close(int fd)
{
  struct file *file = get_file(fd);
  if (!file->deny_close)
  {
    file_close(file);
    file->deny_close = true;
  }
}

bool remove(const char *file)
{
  return filesys_remove(file);
}

void halt(void)
{
  shutdown_power_off();
}

void exit(int status)
{
  struct thread *cur = thread_current();
  if (&cur->parent != NULL)
  {
    struct list_elem *e;
    struct thread *p = cur->parent;
    if (!list_empty(&p->children))
    {
      for (e = list_begin(&p->children); e != list_end(&p->children); e = list_next(e))
      {
        struct child *t = list_entry(e, struct child, child_elem);
        if (t->id == cur->tid)
        {
          t->exited = 1;
          t->status = status;
          // printf("Child id exited: %d\n", (int)t->id);
          break;
        }
      }
      sema_up(&cur->parent->child_wait);
    }
  }
  char *token, *save_ptr;
  token = strtok_r(thread_current()->name, " ", &save_ptr);
  printf("%s: exit(%d)\n", token, status);
  thread_exit();
}

pid_t exec(const char *file)
{
  lock_acquire(&exec_lock);
  pid_t tid = process_execute(file);
  if (tid < 0)
  {
    return -1;
  }
  lock_release(&exec_lock);
  return tid;
}

int wait(pid_t pid)
{
  if (is_user_vaddr(pid))
  {
    pid_t p = process_wait(pid);
    return p;
  }
  else
  {
    return -1;
  }
}

int filesize(int fd)
{
  struct file *file = get_file(fd);
  return file_length(file);
}

void seek(int fd, unsigned position)
{
  if ((int)position >= 0)
  {
    file_seek(get_file(fd), position);
  }
  return 0;
}

unsigned tell(int fd)
{
  return file_tell(get_file(fd));
}

// wait, create, remove
static void
syscall_handler(struct intr_frame *f UNUSED)
{
  void *esp = f->esp;
  int syscall_no = *(int *)esp;

  if (is_memory_safe(esp))
  {
    int syscall_no = *(int *)esp;
    int fd;
    const void *buffer;
    unsigned size;
    int status;
    const char *file;
    unsigned position;

    // printf("Syscall no: %d\n", syscall_no);
    switch (syscall_no)
    {
    case SYS_HALT:
      halt();
      break;
    case SYS_EXIT:
      if (validate_args(esp, 1))
      {
        int status = *(int *)(esp + 4);
        exit(status);
      }
      break;
    case SYS_EXEC:
      if (validate_args(esp, 1))
      {
        char *file_name = *(char **)(esp + 4);
        if (!is_user_vaddr(file_name) || file_name == NULL || !is_memory_safe(file_name))
        {
          exit(-1);
        }
        f->eax = exec(file_name);
      }
      break;
    case SYS_WAIT:
      if (validate_args(esp, 1))
      {
        pid_t pid = *(pid_t *)(esp + 4);
        f->eax = wait(pid);
      }
      break;
    case SYS_CREATE:
      if (validate_args(esp, 2))
      {
        file = *(const char **)(esp + 4);
        size = *(unsigned *)(esp + 8);
        if (is_memory_safe(file))
        {
          f->eax = create(file, size);
        }
        else
        {
          exit(-1);
        }
      }
      break;
    case SYS_REMOVE:
      if (validate_args(esp, 1))
      {
        file = *(const char **)(esp + 4);
        f->eax = remove(file);
      }
      break;
    case SYS_OPEN:
      if (validate_args(esp, 1))
      {
        file = *(const char **)(esp + 4);

        if (is_memory_safe(file))
        {
          f->eax = open(file);
        }
        else
        {
          exit(-1);
        }
        // printf("Filename sysopen: %s\n", file);
      }
      break;
    case SYS_FILESIZE:
      if (validate_args(esp, 1))
      {
        fd = *(int *)(esp + 4);
        f->eax = filesize(fd);
      }
      break;
    case SYS_READ:
      if (validate_args(esp, 1))
      {
        fd = *(int *)(esp + 4);
        buffer = *(const void **)(esp + 8);
        size = *(unsigned *)(esp + 12);
        if (is_user_vaddr(&buffer) && is_memory_safe(buffer) && is_valid_fd(fd))
        {
          f->eax = read(fd, buffer, size);
        }
        else
        {
          exit(-1);
        }
      }
      break;
    case SYS_WRITE:
      if (validate_args(esp, 3))
      {
        fd = *(int *)(esp + 4);
        buffer = *(const void **)(esp + 8);
        size = *(unsigned *)(esp + 12);
        if (is_memory_safe(buffer) && is_valid_fd(fd))
        {
          f->eax = write(fd, buffer, size);
        }
        else
        {
          exit(-1);
        }
      }
      // TODO maybe a lock should be here to prevent other processes from writing to file at the same time?
      break;
    case SYS_SEEK:
      if (validate_args(esp, 2))
      {
        fd = *(int *)(esp + 4);
        position = *(unsigned *)(esp + 8);
        seek(fd, position);
      }
      break;
    case SYS_TELL:
      if (validate_args(esp, 1))
      {
        fd = *(int *)(esp + 4);
        f->eax = tell(fd);
      }
      break;
    case SYS_CLOSE:
      if (validate_args(esp, 1))
      {
        fd = *(int *)(esp + 4);
        if (is_valid_fd(fd))
        {
          close(fd);
        }
      }
      break;
    }
  }
  else
  {
    exit(-1);
  }
}
