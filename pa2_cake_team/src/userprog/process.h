#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

typedef int pid_t; /* A user process's identifier */

/* Argument list of a user program */
struct args
{
  char *user_program_name;
  char **argv;
};

void parse_arguments(const char *line, struct args *arguments);
tid_t process_execute(const char *file_name);
int process_wait(tid_t);
void process_exit(void);
void process_activate(void);
int argv_count(char **argv);

#endif /* userprog/process.h */
