#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT "5000"
#define BACKLOG 5
#define BUFFER_SIZE 1024

enum STATUS_CODE {
    OK,
    NOT_FOUND
};

char * STATUS_MESSAGE[] = {
    "200 OK",
    "404 NOT FOUND"
};

void parse_request(char * req, int req_size, char ** resp, int * resp_size) {
    char * req_line = strsep(&req, "\n");

    char * token = strtok(req_line, " "); // the GET
    token = strtok(NULL, " "); // the index to return
    
    strcat(*resp, "HTTP/1.1 ");

    // puts("First line: ");
    // while(token != NULL) {
    //     printf("%s\n", token);
    // }
    FILE * fp;
    char req_file[100];
    strcpy(req_file, "www");
    if (strcmp(token, "/") == 0) {
        strcat(req_file, "/index.html");
    } else {
        strcat(req_file, token);
    }

    printf("Req file: %s\n", req_file);
    fp = fopen(req_file, "rb");

    // Store the content of the file
    char file_buff[BUFFER_SIZE];

    // If the file exist
    if(fp != NULL) {
        strcat(*resp, STATUS_MESSAGE[OK]);
        strcat(*resp, "\r\n\r\n");
        while(fgets(file_buff, BUFFER_SIZE, fp)) {
            strcat(*resp, file_buff);
        }

        fclose(fp);
    // If the file does not exist
    } else {
        strcat(*resp, STATUS_MESSAGE[NOT_FOUND]);
        strcat(*resp, "\r\n\r\n");
    }


    // *resp = "HTTP/1.1 200 OK\r\n\r\nRequested path: /\r\n";
    *resp_size = strlen(*resp);
}

void handle_client(int new_fd) {
    char *msg = (char *)malloc(BUFFER_SIZE);
    int msg_len;


    char buff[BUFFER_SIZE];
    ssize_t bytes_recv;

    bytes_recv = recv(new_fd, buff, sizeof(buff) - 1, 0);
    if (bytes_recv == -1) {
        perror("recv");
        close(new_fd);
        return;
    }

    // printf("%s\n", buff);
    parse_request(buff, bytes_recv, &msg, &msg_len);
    buff[bytes_recv] = '\0';

    if (send(new_fd, msg, msg_len, 0) == -1) {
        perror("send");
    }

    free(msg);
    close(new_fd);
}

int main(void) {
    struct addrinfo hints, *res, *p;
    int sockfd, new_fd, status;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if ((status = getaddrinfo(NULL, PORT, &hints, &res)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
        return 1;
    }

    for (p = res; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            perror("socket");
            continue;
        }
        
        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("bind");
            continue;
        }

        break;
    }

    freeaddrinfo(res);

    if (p == NULL) {
        fprintf(stderr, "Failed to bind\n");
        return 2;
    }

    if (listen(sockfd, BACKLOG) == -1) {
        perror("listen");
        return 3;
    }

    printf("Waiting for connections...\n");

    struct sockaddr_storage their_addr;
    socklen_t addr_size = sizeof their_addr;

    while (1) {
        new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &addr_size);
        if (new_fd == -1) {
            perror("accept");
            continue;
        }

        if (!fork()) {
            close(sockfd); // Child process doesn't need the listener
            handle_client(new_fd);
            exit(0);
        }
        close(new_fd);
    }

    return 0;
}
