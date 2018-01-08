//  This program is free software; you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation; either version 2 of the License, or
//  (at your option) any later version.
//      
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//      
//  You should have received a copy of the GNU General Public License
//  along with this program; if not, write to the Free Software
//  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
//  MA 02110-1301, USA.
//
//  Author: Matías Fontanini
//  Contact: matias.fontanini@gmail.com


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <signal.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#include <pthread.h>

#define MAXPENDING 200
#define BUF_SIZE 2048
#define USERNAME "username"
#define PASSWORD "password"


/* Command constants */
#define CMD_CONNECT         1
#define CMD_BIND            2
#define CMD_UDP_ASSOCIATIVE 3

/* Address type constants */
#define ATYP_IPV4   1
#define ATYP_DNAME  3
#define ATYP_IPV6   4

/* Connection methods */
#define METHOD_NOAUTH       0
#define METHOD_AUTH         2
#define METHOD_NOTAVAILABLE 0xff

/* Responses */
#define RESP_SUCCEDED       0
#define RESP_GEN_ERROR      1


int SERVER_PORT = 0;

/* Handshake */

struct MethodIdentificationPacket {
    uint8_t version, nmethods;
    /* uint8_t methods[nmethods]; */
} __attribute__((packed));

struct MethodSelectionPacket {
    uint8_t version, method;
} __attribute__((packed));


/* Requests */

struct SOCKS5RequestHeader {
    uint8_t version, cmd, rsv /* = 0x00 */, atyp;
} __attribute__((packed));

struct SOCK5IP4RequestBody {
    uint32_t ip_dst;
    uint16_t port;
} __attribute__((packed));

struct SOCK5DNameRequestBody {
    uint8_t length;
    /* uint8_t dname[length]; */
} __attribute__((packed));


/* Responses */

struct SOCKS5Response {
    uint8_t version, cmd, rsv /* = 0x00 */, atyp;
    uint32_t ip_src;
    uint16_t port_src;
} __attribute__((packed));


pthread_mutex_t get_host_lock;
pthread_mutex_t client_lock;
pthread_cond_t client_cond;
uint32_t client_count = 0, max_clients = 10;

void sig_handler(int signum) {
    
}

int create_listen_socket(int port) {
    int serversock;
    struct sockaddr_in echoserver;
    /* Create the TCP socket */
    if ((serversock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        printf("[-] Could not create socket.\n");
        return -1;
    }
    /* Construct the server sockaddr_in structure */
    memset(&echoserver, 0, sizeof(echoserver));       /* Clear struct */
    echoserver.sin_family = AF_INET;                  /* Internet/IP */
    echoserver.sin_addr.s_addr = htonl(INADDR_ANY);   /* Incoming addr */
    echoserver.sin_port = htons(port);       /* server port */
    /* Bind the server socket */
    if (bind(serversock, (struct sockaddr *) &echoserver, sizeof(echoserver)) < 0) {
        printf("[-] Bind error.\n");
        return -1;
    }
    /* Listen on the server socket */
    if (listen(serversock, MAXPENDING) < 0) {
        printf("[-] Listen error.\n");
        return -1;
    }
    return serversock;
}

int recv_sock(int sock, char *buffer, uint32_t size) {
    int index = 0, ret;
    while(size) {
        if((ret = recv(sock, &buffer[index], size, 0)) <= 0)
            return (!ret) ? index : -1;
        index += ret;
        size -= ret;
    }
    return index;
}

int send_sock(int sock, const char *buffer, uint32_t size) {
    int index = 0, ret;
    while(size) {
        if((ret = send(sock, &buffer[index], size, 0)) <= 0)
            return (!ret) ? index : -1;
        index += ret;
        size -= ret;
    }
    return index;
}

char *int_to_str(uint32_t ip) {
    char *str = malloc(16);
    sprintf(str, "%u.%u.%u.%u", ((ip >> 0 ) & 0xFF),
                                ((ip >> 8 ) & 0xFF),
                                ((ip >> 16 ) & 0xFF),
                                ((ip >> 24 ) & 0xFF));
    return str;
}

int connect_to_host(uint32_t ip, uint16_t port) {
    struct sockaddr_in serv_addr;
    struct hostent *server;
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
        return -1;
    memset((char *) &serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET; 
    char *ip_string = int_to_str(ip);
    
    pthread_mutex_lock(&get_host_lock);
    server = gethostbyname(ip_string);
    if(!server) {
        pthread_mutex_unlock(&get_host_lock);
        return -1;
    }

    memcpy((char *)&serv_addr.sin_addr.s_addr, (char *)server->h_addr, server->h_length);
    pthread_mutex_unlock(&get_host_lock);
    
    serv_addr.sin_port = htons(port);
    return !connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) ? sockfd : -1;
}

int read_variable_string(int sock, uint8_t *buffer, uint8_t max_sz) {
    if(recv_sock(sock, (char*)buffer, 1) != 1 || buffer[0] > max_sz)
        return 0;
    uint8_t sz = buffer[0];
    if(recv_sock(sock, (char*)buffer, sz) != sz)
        return -1;
    return sz;
}

int check_auth(int sock) {
    return 1;
    uint8_t buffer[128];
    if(recv_sock(sock, (char*)buffer, 1) != 1 || buffer[0] != 1)
        return 0;
    int sz = read_variable_string(sock, buffer, 127);
    if(sz == -1)
        return 0;
    buffer[sz] = 0;
    if(strcmp((char*)buffer, USERNAME))
        return 0;
    sz = read_variable_string(sock, buffer, 127);
    if(sz == -1)
        return 0;
    buffer[sz] = 0;
    if(strcmp((char*)buffer, PASSWORD))
        return 0;
    buffer[0] = 1;
    buffer[1] = 0;
    return send_sock(sock, (const char*)buffer, 2) == 2;
}

int handle_handshake(int sock, char *buffer) {
    printf("Handling handshake\n");
    struct MethodIdentificationPacket packet = { 0, 0 };
    int read_size = recv_sock(sock, (char*)&packet, sizeof(struct MethodIdentificationPacket));
    if(read_size != sizeof(struct MethodIdentificationPacket) || packet.version != 5)
        return 0;
    printf("Read 1\n");
    if(recv_sock(sock, buffer, packet.nmethods) != packet.nmethods)
        return 0;
    printf("Read 2\n");
    struct MethodSelectionPacket response = { 5, METHOD_NOTAVAILABLE };
    int i;
    printf("packet.methods = %u\n", packet.nmethods);
    for(i = 0; i < packet.nmethods; ++i) {
//#ifdef ALLOW_NO_AUTH
            if(buffer[i] == METHOD_NOAUTH)
                response.method = METHOD_NOAUTH;
//#endif
        if(buffer[i] == METHOD_AUTH)
            response.method = METHOD_AUTH;
    }
    printf("Response.method = %u\n", response.method);
    if(send_sock(sock, (const char*)&response, sizeof(struct MethodSelectionPacket)) != sizeof(struct MethodSelectionPacket) || response.method == METHOD_NOTAVAILABLE)
        return 0;
    printf("Exiting handshake \n");
    return (response.method == METHOD_AUTH) ? check_auth(sock) : 1;
}

void set_fds(int sock1, int sock2, fd_set *fds) {
    FD_ZERO (fds);
    FD_SET (sock1, fds); 
    FD_SET (sock2, fds); 
}

void do_proxy(int client, int conn, char *buffer) {
    fd_set readfds; 
    int result, nfds = ((client > conn) ? client : conn) + 1;
    set_fds(client, conn, &readfds);
    while ((result = select(nfds, &readfds, 0, 0, 0)) > 0) {
        if (FD_ISSET (client, &readfds)) {
            int recvd = recv(client, buffer, 256, 0);
            if(recvd <= 0)
                return;
            send_sock(conn, buffer, recvd);
        }
        if (FD_ISSET (conn, &readfds)) {
            int recvd = recv(conn, buffer, 256, 0);
            if(recvd <= 0)
                return;
            send_sock(client, buffer, recvd);
        }
        set_fds(client, conn, &readfds);
    }
}

int handle_request(int sock, char *buffer) {
    printf("Handling request\n");
    struct SOCKS5RequestHeader header = { 0 };
    recv_sock(sock, (char*)&header, sizeof(struct SOCKS5RequestHeader));
    printf("version = %u, cmd = %u, atyp = %u\n", header.version, header.cmd, header.atyp);
    if(header.version != 5 || header.cmd != CMD_CONNECT || header.rsv != 0)
        return 0;
    int client_sock = -1;
    switch(header.atyp) {
        case ATYP_IPV4:
        {
            struct SOCK5IP4RequestBody req;
            if(recv_sock(sock, (char*)&req, sizeof(struct SOCK5IP4RequestBody)) != sizeof(struct SOCK5IP4RequestBody))
                return 0;
            client_sock = connect_to_host(req.ip_dst, ntohs(req.port));
            break;
        }
        case ATYP_DNAME:
            break;
        default:
            return 0;
    }
    if(client_sock == -1)
        return 0;
    struct SOCKS5Response response = { 5, RESP_SUCCEDED, 0, ATYP_IPV4, 0, 0 };
    response.ip_src = 0;
    response.port_src = SERVER_PORT;
    send_sock(sock, (const char*)&response, sizeof(struct SOCKS5Response));
    do_proxy(client_sock, sock, buffer);
    shutdown(client_sock, SHUT_RDWR);
    close(client_sock);
    return 1;
}

void *handle_connection(void *arg) {
    printf("Connection handler\n");
    int sock = (uint64_t)arg;
    char *buffer = malloc(BUF_SIZE);
    if(handle_handshake(sock, buffer))
        handle_request(sock, buffer);
    shutdown(sock, SHUT_RDWR);
    close(sock);
    free(buffer);
    pthread_mutex_lock(&client_lock);
    client_count--;
    if(client_count == max_clients - 1)
        pthread_cond_signal(&client_cond);
    pthread_mutex_unlock(&client_lock);
    return 0;
}

int spawn_thread(pthread_t *thread, void *data) {
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 64 * 1024);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    return !pthread_create(thread, &attr, handle_connection, data);
}

int main(int port) {
    SERVER_PORT = 4444;
    struct sockaddr_in echoclient;
    int listen_sock = create_listen_socket(SERVER_PORT);
    printf("Listening socket created\n");
    if(listen_sock == -1) {
        printf("[-] Failed to create server\n");
        return 1;
    }

    signal(SIGPIPE, sig_handler);
    
    pthread_mutex_init(&get_host_lock, NULL);
    pthread_mutex_init(&client_lock, 0);
    pthread_cond_init(&client_cond, 0);

    while(1) {
        uint32_t clientlen = sizeof(echoclient);
        int clientsock;
        pthread_mutex_lock(&client_lock);
        if(client_count == max_clients)
            pthread_cond_wait(&client_cond, &client_lock);
        pthread_mutex_unlock(&client_lock);
        if ((clientsock = accept(listen_sock, (struct sockaddr *) &echoclient, &clientlen)) > 0) {
            printf("Accepted connection\n");
            pthread_mutex_lock(&client_lock);
            client_count++;
            pthread_mutex_unlock(&client_lock);
            pthread_t thread;
            printf("Spawning thread\n");
            spawn_thread(&thread, (void*)clientsock);
        }
    }
}

