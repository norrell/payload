#ifndef HTTP_CLIENT_BEACON_H
#define HTTP_CLIENT_BEACON_H

//extern int ID;
#include "command.h"

char *get_beacon(void);
int get_commands(char *beacon_response, struct command **cmds);
#endif
