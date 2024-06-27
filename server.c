#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <pthread.h>
#define SERVPORT 3333//定义端口号
#define BACKLOG 10//请求队列中允许的最大请求数
#define MAXDATASIZE 5//数据长度

void* handle_request(void* client_fd_addr);
int main() {
    struct sockaddr_in server_sockaddr,client_sockaddr;//声明服务器和客户端的socket存储结构
    int sin_size,recvbytes;
    int sockfd,client_fd;//socket描述符


    if((sockfd = socket(AF_INET,SOCK_STREAM,0)) == -1) {//建立socket链接
        perror("Socket");
        exit(1);
    }

    printf("Socket success!,sockfd=%d\n",sockfd);

    //以sockaddt_in结构体填充socket信息
    server_sockaddr.sin_family = AF_INET;//IPv4
    server_sockaddr.sin_port = htons(SERVPORT);//端口
    server_sockaddr.sin_addr.s_addr = INADDR_ANY;//本主机的任意IP都可以使用

    if((bind(sockfd,(struct sockaddr *)&server_sockaddr,sizeof(struct sockaddr))) == -1) {//bind函数绑定
        perror("bind");
        exit(-1);
    }

    printf("bind success!\n");

    if(listen(sockfd,BACKLOG) == -1) {//监听
        perror("listen");
        exit(1);
    }

    printf("listening ... \n");

    while (1) {
        if((client_fd = accept(sockfd,(struct sockaddr *) &client_sockaddr,&sin_size)) == -1) {//等待客户端链接
            perror("accept");
            exit(1);
        }
        printf("accept success!\n");
        pthread_t tid; /* thread identifier */
        /* create the thread */
        pthread_create(&tid, NULL, handle_request, &client_fd);

    }

    close(sockfd);
}

void* handle_request(void* client_fd_addr) {
    int client_fd = *(int *)client_fd_addr;
    while (1) {
        char* buffer = calloc(MAXDATASIZE, sizeof(char));
        recv(client_fd,buffer,MAXDATASIZE,0);
        //检查dns表
        //char* result = check_dns(buffer);
        strcpy(buffer, "mock result\0");
        if (send(client_fd, buffer, strlen(buffer)+1, MSG_NOSIGNAL) == -1) {
            break;
        }
        free(buffer);
    }
    close(client_fd);
}