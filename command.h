#ifndef HTTP_CLIENT_COMMAND_H
#define HTTP_CLIENT_COMMAND_H

extern int timeout;

struct command {
	struct command *next;
	int id;
	char *type;
	char *param;
	int ret;
};

void exec_commands(char *beacon_response);

#endif
