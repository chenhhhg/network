#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <pthread.h>
#define SERVPORT 2333//定义端口号
#define BACKLOG 10//请求队列中允许的最大请求数
#define MAXDATASIZE 5//数据长度

//dns报文Header部分数据结构
struct dns_header{
    unsigned short id; //2字节（16位）
    unsigned short flags;

    unsigned short questions; //问题数
    unsigned short answer; //回答数

    unsigned short authority;
    unsigned short additional;
};

//dns报文Queries部分的数据结构
struct dns_question{
    int length; //主机名的长度，自己添加的，便于操作
    unsigned short qtype;
    unsigned short qclass;
    //查询名是长度和域名组合
    //如www.0voice.com ==> 60voice3com0
    //之所以这么做是因为域名查询一般是树结构查询，com顶级域，0voice二级域
    unsigned char *name; // 主机名（长度不确定）
};

//dns响应报文中数据（域名和ip）的结构体
struct dns_item{
    char *domain;
    char *ip;
};



void* handle_request(void* client_fd_addr);
int dns_create_header(struct dns_header *header);
int dns_create_question(struct dns_question *question, const char *hostname);
int dns_build_requestion(struct dns_header *header, struct dns_question *question, char *request, int rlen);
int dns_client_commit(const char *domain);

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
        if (send(client_fd, buffer, strlen(buffer)+1, MSG_NOSIGNAL) == -1l) {
            break;
        }
        free(buffer);
    }
    close(client_fd);
    printf("connect has been closed\n");
}

int dns_client_commit(const char *domain)
{
    //下方流程是基本定死的套路
    //1.创建UDP socket
    //网络层ipv4, 传输层用udp
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0)
    {
        return -1;
    }

    //2.结构体填充数据
    struct sockaddr_in servaddr;
    bzero(&servaddr, sizeof(servaddr)); //将结构体数组清空
    servaddr.sin_family = AF_INET; 
    servaddr.sin_port = htons(DNS_SERVER_PORT);
    //点分十进制地址转为网络所用的二进制数 替换inet_pton
    //servaddr.sin_addr.s_addr = inet_addr(DNS_SERVER_IP);
    inet_pton(AF_INET, DNS_SERVER_IP, &servaddr.sin_addr.s_addr);

    //UDP不一定要connect，只是这样提高成功发送请求的可能性
    connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr));


    //3.dns报文的数据填充
    struct dns_header header = {0};
    dns_create_header(&header);

    struct dns_question question = {0};

    dns_create_question(&question, domain);

    char request[1024] = {0};
    int len = dns_build_requestion(&header, &question, request, 1024);

    //4.通过sockfd发送DNS请求报文
    int slen = sendto(sockfd, request, len, 0, (struct sockaddr *)&servaddr, sizeof(struct sockaddr));

    char response[1024] = {0};
    struct sockaddr_in addr;
    size_t addr_len = sizeof(struct sockaddr_in);

    //5.接受DNS服务器的响应报文
    //addr和addr_len是输出参数
    int n = recvfrom(sockfd, response, sizeof(response), 0, (struct sockaddr *)&addr, (socklen_t *)&addr_len);

    struct dns_item *dns_domain = NULL;
    //6.解析响应
    dns_parse_response(response, &dns_domain);

    free(dns_domain);
    
    return n; //返回接受到的响应报文的长度
}

//将header部分字段填充数据
int dns_create_header(struct dns_header *header)
{
    if(header == NULL)
        return -1;
    memset(header, 0x00, sizeof(struct dns_header));

    //id用随机数,种子用time(NULL),表明生成随机数的范围
    srandom(time(NULL)); // 线程不安全
    header->id = random();

    //网络字节序（大端）:地址低位存数据高位;主机字节序则与之相反
    //主机(host)字节序转网络(net)字节序
    header->flags = htons(0x0100);
    header->questions = htons(1);
    return 0;
}

int dns_create_question(struct dns_question *question, const char *hostname)
{
    if(question == NULL || hostname == NULL)
        return -1;
    memset(question, 0x00, sizeof(struct dns_question));

    //内存空间长度：hostname长度 + 结尾\0 再多给一个空间
    question->name = (char *)malloc(strlen(hostname) + 2);
    if(question->name == NULL)
    {
        return -2;
    }

    question->length = strlen(hostname) + 2;

    //查询类型1表示获得IPv4地址
    question->qtype = htons(1);
    //查询类1表示Internet数据
    question->qclass = htons(1);

    //【重要步骤】
    //名字存储：www.0voice.com -> 3www60voice3com
    const char delim[2] = ".";
    char *qname = question->name; //用于填充内容用的指针

    //strdup先开辟大小与hostname同的内存，然后将hostname的字符拷贝到开辟的内存上
    char *hostname_dup = strdup(hostname); //复制字符串，调用malloc
    //将按照delim分割出字符串数组，返回第一个字符串
    char *token = strtok(hostname_dup, delim);

    while(token != NULL)
    {
        //strlen返回字符串长度不含'\0'
        size_t len = strlen(token);

        *qname = len;//长度的ASCII码
        qname++;

        //将token所指的字符串复制到qname所指的内存上，最多复制len + 1长度
        //len+1使得最后一个字符串把\0复制进去
        strncpy(qname, token, len + 1);
        qname += len;

        //固定写法，此时内部会获得下一个分割出的字符串返回（strtok会依赖上一次运行的结果）
        token = strtok(NULL, delim); //依赖上一次的结果，线程不安全
    }

    free(hostname_dup);
}

//将header和question合并到request中
//header [in]
//question [in]
//request [out]
//rlen:代表request的大小
int dns_build_requestion(struct dns_header *header, struct dns_question *question, char *request, int rlen){
    if (header == NULL || question == NULL || request == NULL)
        return -1;

    memset(request, 0, rlen);

    //header -> request
    memcpy(request, header, sizeof(struct dns_header));
    int offset = sizeof(struct dns_header);

    //Queries部分字段写入到request中，question->length是question->name的长度
    memcpy(request + offset, question->name, question->length);
    offset += question->length;

    memcpy(request + offset, &question->qclass, sizeof(question->qclass));
    offset += sizeof(question->qclass);

    memcpy(request + offset, &question->qtype, sizeof(question->qtype));
    offset += sizeof(question->qtype);

    return offset; //返回request数据的实际长度
}
