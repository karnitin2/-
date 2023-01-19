#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "md5.h"



/*!
    @brief Function launching the client and connecting to the server
    @param ip_addr - string containing server IP address
    @param port - port number
    @return socket file descriptor on success, -1 otherwise
*/
int client_launch(const char* ip_addr, uint16_t port) {
    int res = 0;
    int socket_fd = 0;
    struct sockaddr_in addr;
    uint32_t addr_len = 0;

    socket_fd = socket(AF_INET, SOCK_STREAM, 0);

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    res = inet_aton(ip_addr, &addr.sin_addr);
    if (res < 0) {
        printf("Incorrect IP address\n");
        return -1;
    }

    res = connect(socket_fd, (struct sockaddr*) &addr, sizeof(addr));
    if (res < 0) {
        printf("Connection failed!\n");
        return -1;
    }

    return socket_fd;
}


/*!
    @brief salt value length
*/
#define SALT_LEN 16

/*!
    @brief maximum password length
*/
#define MAX_PWD_LEN 20


/*!
    @brief authenticating and sending vectors data
    @param socket_fd - socket file descriptor
    @return none
*/
void send_vectors(int socket_fd) {
    int res, client_fd, bytes_read = 0;
    struct sockaddr_in addr;
    unsigned int addr_len = 0;
    uint32_t vec_num = 1;
    uint32_t vec_len = 5;
    double* vec_nums = NULL;
    double factor = 0;
    char pwd[SALT_LEN + MAX_PWD_LEN] = "";
    char id[MAX_PWD_LEN] = "";

    vec_nums = calloc(5, sizeof(double));

    for (int i = 0; i < vec_len; ++i) {
        vec_nums[i] = i + 5;
    }

    printf("Enter id\n");
    scanf("%s", id);

    send(socket_fd, id, strlen(id) + 1, 0);

    res = recv(socket_fd, pwd, SALT_LEN, 0);
    if (res < 0) {
        printf("recv failed\n");
    }

    if (strcmp(pwd, "ERR") == 0) {
        printf("Wrong ID!\n");
        return;
    }

    printf("Enter password\n");
    scanf("%s", pwd + SALT_LEN);

    char* hash = md5(pwd, strlen(pwd));

    send(socket_fd, hash, SALT_LEN, 0);

    res = recv(socket_fd, pwd, MAX_PWD_LEN, 0);
    if (res < 0) {
        printf("Error: receiving data failed!\n");
        return;
    }
    if (strcmp(pwd, "ERR") == 0) {
        printf("Error: Incorrect password!\n");
        return;
    } else if (strcmp(pwd, "OK") == 0) {
        printf("Authentification success!\n");
    }

    send(socket_fd, &vec_num, sizeof(vec_num), 0);
    send(socket_fd, &vec_len, sizeof(vec_len), 0);
    send(socket_fd, vec_nums, sizeof(double) * 5, 0);
    res = recv(socket_fd, &factor, sizeof(factor), 0);
    if (res < 0) {
        printf("recv failed\n");
        return;
    } 

    free(vec_nums);
    printf("Factor: %lf\n", factor);
}

int main(int argc, char* argv[]) {
    int fd, res = 0;
    if (argc != 4) {
        printf("USAGE: ./server IP_ADDRESS PORT FILE_LOGINS_PWDS\n");
        return 0;
    }

    printf("Launching client...\n");
    fd = client_launch(argv[1], (uint16_t) strtoul(argv[2], NULL, 10));
    if (fd < 0) {
        printf("Client not launched!\n");
        return 1;
    }

    printf("Client successfully connected!\n");
    send_vectors(fd);

    shutdown(fd, SHUT_RDWR);
    close(fd);
    
    return 0;
}
