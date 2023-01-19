/*!
    @brief Server program
    @author Ilya Uchastkin
*/
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#include "md5.h"

#define MAX_LISTEN 10
#define DEFAULT_PORT 33333
#define MAX_FILE_NAME 256

typedef struct {
    int fd;
    FILE* flog;
    char** ids;
    char** pwds;
    size_t size;
} server_t;


/*!
 * @brief Levels of errors for logging
 * @param SERVER_INFO Just some server information 
 * @param SERVER_WARN Warning, not an error
 * @param SERVER_ERR  Error occured, not falling down the server
 * @param SERVER_ALERT Critical error, logged before terminating the server
 * 
*/
enum server_err {
    SERVER_INFO = 0,
    SERVER_WARN,
    SERVER_ERR,
    SERVER_ALERT
};

/*!
 * @brief Log the message
 */
#define SERVER_LOG(level, ...) { time_t t = time(NULL); \
    struct tm* tm = localtime(&t); \
    fprintf(server->flog, "%d-%02d-%02d %02d:%02d:%02d %s: ", \
        tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec,\
        #level); \
    fprintf(server->flog, __VA_ARGS__);}


/*! @brief Function launching the server 
    @param ip_addr - IP-address
    @param port - port number (in Little Endian)
    @param log_file - file name to print logs to
    @param server - pointer to server_t data structure
    @return server socket file descriptor on success; -1 otherwise
*/
int server_launch(const char* ip_addr, uint16_t port, const char* log_file, server_t* server) {
    int res = 0;
    int socket_fd = 0;
    struct sockaddr_in addr;

    server->flog = fopen(log_file, "w");
    if (!server->flog) {
        printf("Opening file to log to failed, defaulting to stdout\n");
        server->flog = stdout;
    }
    printf("logfile %s\n", log_file);

    SERVER_LOG(SERVER_INFO, "logging started\n");

    server->fd = socket(AF_INET, SOCK_STREAM, 0);

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    res = inet_aton(ip_addr, &addr.sin_addr);
    if (res < 0) {
        SERVER_LOG(SERVER_ALERT, "Incorrect IP address!\n");
        return -1;
    }
    res = bind(server->fd, (struct sockaddr*) &addr, sizeof(addr));
    if (res < 0) {
        SERVER_LOG(SERVER_ALERT, "Error: binding to address %s failed!\n", ip_addr);
        return -1;
    }

    res = listen(server->fd, MAX_LISTEN);
    if (res < 0) {
        SERVER_LOG(SERVER_ALERT, "Error: listen system call failed!\n");
        return -1;
    }

    return server->fd;
}


/*!
    @brief Maximum identificator length
*/
#define MAX_ID_LENGTH 20
/*!
    @brief ERR response string sent by server
*/
const char* RESP_ERR = "ERR";
/*!
    @brief OK response string sent by server
*/
const char* RESP_OK = "OK";
/*!
    @brief Length of salt and MD5 hash
*/
#define MD5_LENGTH 16


/*! @brief Authenticating a client 
    @param client_fd - client connection file descriptor
    @param ids - array of identifiers
    @param pwds - array of passwords
    @param size - size of arrays of identifiers and passwords
    @return 1 on success, 0 otherwise
*/
int authenticate(int client_fd, server_t* server) {
    int res, verificator;
    char id[MAX_ID_LENGTH];
    char* salt = NULL;
    unsigned short temp = 0;
    char md5_return[MD5_LENGTH] = "";
    int index = 0;

    verificator = 0;

    res = recv(client_fd, id, MAX_ID_LENGTH, 0);
    if (res < 0) {
        SERVER_LOG(SERVER_ERR, "Error %d: Reading from socket failed!\n", errno);
        return 0;
    }

    // Checking the correctness of returned ID
    for (int i = 0; i < server->size; ++i) {
        if (strcmp(server->ids[i], id) == 0) {
            verificator = 1;
            index = i;
            break;
        }
    }

    if (!verificator) {
        SERVER_LOG(SERVER_INFO, "Incorrect ID!\n");
        send(client_fd, RESP_ERR, strlen(RESP_ERR) + 1, 0);
        return verificator;
    }

    // Checking the correctness of the password
    salt = calloc(17 + MAX_ID_LENGTH, sizeof(char));
    if (!salt) {
        SERVER_LOG(SERVER_ERR, "Error %d: Memory allocation failed!\n", errno);
        return 0;
    }

    for (int i = 0; i < 4; ++i) {
        temp = rand();
        sprintf(salt + i * 4, "%04X", temp);
    }

    send(client_fd, salt, 16, 0);
    res = recv(client_fd, md5_return, MD5_LENGTH, 0);

    char* result = NULL;
    memcpy(salt + 16, server->pwds[index], strlen(server->pwds[index]));
    result = md5(salt, 16 + strlen(server->pwds[index]));

    verificator = 0;
    if (strncmp(md5_return, result, 16) == 0) {
        SERVER_LOG(SERVER_INFO, "Password correct!\n");
        verificator = 1;
    }

    return verificator;
}


/*!
    @brief Function containing the server loop accepting the client connections and handling them
    @param socket_fd - server socket file descriptor
    @param ids - identificators array
    @param pwds - passwords array
    @param size - size of ids and pwds arrays
    @return none
*/
void server_main(server_t* server) {
    int res, client_fd, bytes_read = 0;
    struct sockaddr_in addr;
    unsigned int addr_len = 0;
    uint32_t vec_num = 0;
    uint32_t vec_len = 0;
    double* vec_nums = NULL;
    double factor = 0;

    while (1) {
        SERVER_LOG(SERVER_INFO, "Accepting connections\n");
        client_fd = accept(server->fd, (struct sockaddr*) &addr, &addr_len);
        if (client_fd < 0) {
            SERVER_LOG(SERVER_ERR, "Accept syscall failed! Error %d\n", errno);
            break;
        }

        res = authenticate(client_fd, server);
        if (!res) {
            SERVER_LOG(SERVER_INFO, "Authentification failed!\n");
            send(client_fd, RESP_ERR, strlen(RESP_ERR) + 1, 0);
            close(client_fd);
            continue;
        } else {
            SERVER_LOG(SERVER_INFO, "Authentification succeeded!\n");
            send(client_fd, RESP_OK, strlen(RESP_OK) + 1, 0);
        }

        res = recv(client_fd, &vec_num, sizeof(uint32_t), 0);
        if (res < 0) {
            SERVER_LOG(SERVER_ERR, "Error: %d: Reading from socket failed!\n", errno);
            close(client_fd);
            continue;
        }

        for (int i = 0; i < vec_num; ++i) {
            res = recv(client_fd, &vec_len, sizeof(uint32_t), 0);
            if (res < 0) {
                SERVER_LOG(SERVER_ERR, "Error %d: Reading from socket failed!\n", errno);
                close(client_fd);
                break;
            }

            vec_nums = calloc(vec_len, sizeof(double));
            factor = 1;

            res = recv(client_fd, vec_nums, vec_len * sizeof(double), 0);
            if (res < 0) {
                SERVER_LOG(SERVER_ERR, "Error %d: Reading from socket failed!\n", errno);
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


void print_usage() {
    printf("USAGE: ./server IP_ADDRESS -p PORT -f FILE_LOGINS_PWDS -l LOG_FILE\n");
}


const int MAX_SIZE = 1000;
int main(int argc, char* argv[]) {
    int fd, res = 0;
    server_t server;
    char* ip_addr = NULL;
    char* logfile = NULL;
    char* datafile = NULL;
    uint16_t port = 0;
    memset(&server, 0, sizeof(server));

    if (argc == 1) {
        print_usage();
        return 0;
    }

    ip_addr = argv[1];

    char opt = 0;
    while ((opt = getopt(argc, argv, "hplf")) != -1) {
        switch (opt) {
            case 'h':
                print_usage();
                return 0;
            case 'p':
                if (!port) {
                    port = strtoul(argv[optind], NULL, 10);
                }
                break;
            case 'l':
                if (!logfile) {
                    logfile = argv[optind];
                }
                break;
            case 'f':
                if (!datafile) {
                    datafile = argv[optind];
                }
                break;
            default:
                print_usage();
                return 0;
        }

    }

    if (!port) {
        port = DEFAULT_PORT;
    }

    if (!logfile) {
        logfile = "log.txt";
    }

    if (!datafile) {
        datafile = "logindata.txt";
    }

    FILE* fin = fopen(datafile, "r");

    server.ids = calloc(MAX_SIZE, sizeof(char*));
    if (!server.ids) {
        printf("Allocation failed!\n");
        return 1;
    }
    
    server.pwds = calloc(MAX_SIZE, sizeof(char*));
    if (!server.pwds) {
        printf("Allocation failed!\n");
        return 1;
    }

    for (int i = 0; i < MAX_SIZE; ++i) {
        server.ids[i] = calloc(MAX_ID_LENGTH, sizeof(char));
        if (!server.ids[i]) {
            printf("Allocation failed!\n");
            return 1;
        }

        server.pwds[i] = calloc(MAX_ID_LENGTH, sizeof(char));
        if (!server.pwds[i]) {
            printf("Allocation failed!\n");
            return 1;
        }
        
        if (fscanf(fin, "%s", server.ids[i]) == EOF) {
            break;
        }
        fscanf(fin, "%s", server.pwds[i]);
        ++server.size;
    }

    fclose(fin);

    printf("Launching server...\n");
    fd = server_launch(ip_addr, port, logfile, &server);
    if (fd < 0) {
        printf("Server not launched!\n");
        return 1;
    }

    printf("Server successfully set up!\n");
    server_main(&server);

    shutdown(fd, SHUT_RDWR);
    close(fd);
   
    return 0;
}
