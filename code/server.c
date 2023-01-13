#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

#include "md5.h"

#define MAX_LISTEN 10


int server_launch(const char* ip_addr, uint16_t port) {
    int res = 0;
    int socket_fd = 0;
    struct sockaddr_in addr;

    socket_fd = socket(AF_INET, SOCK_STREAM, 0);

    addr.sin_family = AF_INET;
    addr.sin_port = port;
    res = inet_aton(ip_addr, &addr.sin_addr);
    if (res < 0) {
        printf("Incorrect IP address\n");
        return -1;
    }

    res = bind(socket_fd, (struct sockaddr*) &addr, sizeof(addr));
    if (res < 0) {
        printf("Error: binding to address %s failed!\n", ip_addr);
        return -1;
    }

    res = listen(socket_fd, MAX_LISTEN);
    if (res < 0) {
        printf("Error: listen system call failed!\n");
        return -1;
    }

    return socket_fd;
}

#define MAX_ID_LENGTH 20
const char* RESP_ERR = "ERR";
const char* RESP_OK = "OK";
#define MD5_LENGTH 16

int authenticate(int client_fd, char** ids, char** pwds, size_t size) {
    int res, verificator;
    char id[MAX_ID_LENGTH];
    char* salt = NULL;
    unsigned short temp = 0;
    char md5_return[MD5_LENGTH] = "";
    int index = 0;

    verificator = 0;

    res = recv(client_fd, id, MAX_ID_LENGTH, 0);
    if (res < 0) {
        printf("Error: Reading from socket failed!\n");
        return 0;
    }

    // Checking the correctness of returned ID
    for (int i = 0; i < size; ++i) {
        if (strcmp(ids[i], id) == 0) {
            verificator = 1;
            index = i;
            break;
        }
    }

    if (!verificator) {
        printf("Incorrect ID!\n");
        send(client_fd, RESP_ERR, strlen(RESP_ERR) + 1, 0);
        return verificator;
    }

    // Checking the correctness of the password
    salt = calloc(17 + MAX_ID_LENGTH, sizeof(char));
    if (!salt) {
        printf("Error: Memory allocation failed!\n");
        return 0;
    }

    for (int i = 0; i < 4; ++i) {
        temp = rand();
        sprintf(salt + i * 4, "%04X", temp);
    }

    send(client_fd, salt, 16, 0);
    res = recv(client_fd, md5_return, MD5_LENGTH, 0);

    char* result = NULL;
    memcpy(salt + 16, pwds[index], strlen(pwds[index]));
    result = md5(salt, 16 + strlen(pwds[index]));

    verificator = 0;
    if (strncmp(md5_return, result, 16) == 0) {
        printf("Password correct!\n");
        verificator = 1;
    }

    return verificator;
}

void server_main(int socket_fd, char** ids, char** pwds, size_t size) {
    int res, client_fd, bytes_read = 0;
    struct sockaddr_in addr;
    unsigned int addr_len = 0;
    uint32_t vec_num = 0;
    uint32_t vec_len = 0;
    double* vec_nums = NULL;
    double factor = 0;

    while (1) {
        printf("Accepting connections\n");
        client_fd = accept(socket_fd, (struct sockaddr*) &addr, &addr_len);
        if (client_fd < 0) {
            printf("Accept syscall failed!\n");
            break;
        }

        res = authenticate(client_fd, ids, pwds, size);
        if (!res) {
            printf("Authentification failed!\n");
            send(client_fd, RESP_ERR, strlen(RESP_ERR) + 1, 0);
            close(client_fd);
            continue;
        } else {
            printf("Authentification succeeded!\n");
            send(client_fd, RESP_OK, strlen(RESP_OK) + 1, 0);
        }

        res = recv(client_fd, &vec_num, sizeof(uint32_t), 0);
        if (res < 0) {
            printf("Reading from socket failed!\n");
            close(client_fd);
            break;
        }

        for (int i = 0; i < vec_num; ++i) {
            res = recv(client_fd, &vec_len, sizeof(uint32_t), 0);
            if (res < 0) {
                printf("Error: Reading from socket failed!\n");
                close(client_fd);
                break;
            }

            vec_nums = calloc(vec_len, sizeof(double));
            factor = 1;

            res = recv(client_fd, vec_nums, vec_len * sizeof(double), 0);
            if (res < 0) {
                printf("Error: Reading from socket failed!\n");
                close(client_fd);
                break;
            }

            for (int i = 0; i < vec_len; ++i) {
                factor *= vec_nums[i];
            }

            send(client_fd, &factor, sizeof(double), 0);
            close(client_fd);
            free(vec_nums);
        }
    }
    
}

int main(int argc, char* argv[]) {
    int fd, res = 0;
    int size = 0;
    char** ids = NULL;
    char** pwds = NULL;

    if (argc != 4) {
        printf("USAGE: ./server IP_ADDRESS PORT FILE_LOGINS_PWDS\n");
        return 0;
    }

    FILE* fin = fopen(argv[3], "r");
    fscanf(fin, "%d", &size);
    ids = calloc(size, sizeof(char*));
    if (!ids) {
        printf("Allocation failed!\n");
        return 1;
    }
    
    pwds = calloc(size, sizeof(char*));
    if (!pwds) {
        printf("Allocation failed!\n");
        return 1;
    }

    for (int i = 0; i < size; ++i) {
        ids[i] = calloc(MAX_ID_LENGTH, sizeof(char));
        if (!ids[i]) {
            printf("Allocation failed!\n");
            return 1;
        }

        pwds[i] = calloc(MAX_ID_LENGTH, sizeof(char));
        if (!pwds[i]) {
            printf("Allocation failed!\n");
            return 1;
        }
        
        fscanf(fin, "%s", ids[i]);
        fscanf(fin, "%s", pwds[i]);
    }

    fclose(fin);

    printf("Launching server...\n");
    fd = server_launch(argv[1], (uint16_t) strtoul(argv[2], NULL, 10));
    if (fd < 0) {
        printf("Server not launched!\n");
        return 1;
    }

    printf("Server successfully set up!\n");
    server_main(fd, ids, pwds, size);

    shutdown(fd, SHUT_RDWR);
    close(fd);
   
    printf("Hello, world!\n");
    return 0;
}
