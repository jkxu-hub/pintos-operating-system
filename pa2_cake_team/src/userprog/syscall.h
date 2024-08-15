#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "threads/thread.h"
#include "userprog/process.h"
#include "threads/synch.h"

// struct lock exec_lock;

void syscall_init(void);

/* Projects 2 and later. */
// void exit (int status) NO_RETURN;
// int wait(pid_t pid);
// bool create (const char *file, unsigned initial_size);
// bool remove (const char *file);
// int open (const char *file);
// int filesize (int fd);
// int read (int fd, void *buffer, unsigned length);
// int write (int fd, const void *buffer, unsigned length);
// void seek (int fd, unsigned position);
// unsigned tell (int fd);
// void close (int fd);

void halt(void);
pid_t exec(const char *file);
void exit(int status);
int write(int fd, const void *buffer, unsigned length);

#endif /* userprog/syscall.h */
