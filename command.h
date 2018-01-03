#ifndef HTTP_CLIENT_COMMAND_H
#define HTTP_CLIENT_COMMAND_H

#include <sys/types.h>
#include <signal.h>

extern int timeout;

struct command {
	struct command *next;
	int id;
	char *type;
	char *param;
	int ret;
};

struct process {
	pid_t pid;
	volatile sig_atomic_t is_alive;
};

void parse_and_exec(char *beacon_response);

#endif
