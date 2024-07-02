#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <pthread.h>
#include <netdb.h>
#include  <arpa/inet.h>
#define SERVPORT 2333//定义端口号
#define BACKLOG 10//请求队列中允许的最大请求数
#define MAXDATASIZE 100//数据长度
#define DEFAULT_SERVER_IP "127.0.0.53"
#define MESSAGE_SIZE 1024 //DNS message size
#define DNS_HOST 0x01
#define DNS_CNAME 0x05

//class define
struct dns_item {
	char *domain;
	char *ip;
};
struct dns_header {

    unsigned short id;
    unsigned short flags;

    unsigned short questions;
    unsigned short answer;

    unsigned short authority;
    unsigned short additional;

};
struct dns_question {
    int length;
    unsigned short qtype;
    unsigned short qclass;
    unsigned char *name;
};

//method declare
void handle_request(void* client_fd_addr);
char* get_dns_result(char* buffer);
int dns_create_header(struct dns_header *header);
int dns_create_question(struct dns_question* question,const char* hostname);
int dns_build_requestion(struct dns_header* header,struct dns_question* question,char* request,int rlen);
int dns_client_commit(const char* domin, char* resp);
void dns_parse_name(unsigned char *chunk, unsigned char *ptr, char *out, int *len);
int dns_parse_response(char *buffer, struct dns_item **domains);

//global varieble
char* server_ip = NULL;
int debug = 0;
int ttl=64;

int main(int argc,char *argv[]) {
    struct sockaddr_in server_sockaddr,client_sockaddr;//声明服务器和客户端的socket存储结构
    socklen_t sin_size;
    int sockfd,client_fd;//socket描述符
    server_ip = calloc(30, sizeof(char));

    char command_to_exc = 0;
    for (int i=1;i<argc;i++) {
        char *pchar = argv[i];
        switch(pchar[0]){
            case '-': {
                switch (pchar[1]) {
                    //single command
                    case 'd': {
                        debug=1;
                        break;
                    }
                    default: {
                        command_to_exc=pchar[1];
                        break;
                    }
                }
                break;
            }
            default: {
                switch (command_to_exc) {
                    //command with input
                    case 'i': {
                        strcpy(server_ip, pchar);
                        break;
                    }
                    default:
                        break;
                }
            }
        }
    }

    if (debug) {
        printf("server_ip:%s\n",server_ip);
    }

    if((sockfd = socket(AF_INET,SOCK_STREAM,0)) == -1) {//get socket from Linux
        perror("Socket");
        exit(1);
    }

    if (debug) {
    	printf("Socket success!,sockfd=%d\n",sockfd);
    }

    //以sockaddt_in结构体填充socket信息
    server_sockaddr.sin_family = AF_INET;//IPv4
    server_sockaddr.sin_port = htons(SERVPORT);//端口
    server_sockaddr.sin_addr.s_addr = INADDR_ANY;//本主机的任意IP都可以使用

    if(bind(sockfd,(struct sockaddr *)&server_sockaddr,sizeof(struct sockaddr)) == -1) {//bind函数绑定
        perror("bind");
        exit(-1);
    }

    if (debug) {
    	printf("bind success!\n");
    }

    if(listen(sockfd,BACKLOG) == -1) {//监听
        perror("listen");
        exit(1);
    }

    if (debug) {
    	printf("listening ... \n");
    }

    while (1) {
        if((client_fd = accept(sockfd,(struct sockaddr *) &client_sockaddr,&sin_size)) == -1) {//等待客户端链接
            perror("accept");
            exit(1);
        }
        printf("accept success!\n");
        pthread_t tid;
        pthread_create(&tid, NULL, handle_request, &client_fd);
		if (debug) {
			printf("thread %lu is handling connection %d\n",tid, client_fd);
		}
    }
    close(sockfd);
}

void handle_request(void* client_fd_addr) {
    int client_fd = *(int *)client_fd_addr;
    while (1) {
        char* buffer = calloc(MAXDATASIZE, sizeof(char));
        recv(client_fd,buffer,MAXDATASIZE,0);
        //检查dns表
        char* result = get_dns_result(buffer);
        if(result == NULL) {
        	char* response=NULL;
            int res = dns_client_commit(buffer, response);
        	if (res != 0) {
				strcpy(buffer, "domain name dealing failed!");
        		break;
        	}
        	//dns_parse_response(response, )
        }else if (strcmp(result, "0.0.0.0") == 0) {
            strcpy(buffer, "domain name not exist!");
        }else {
            strcpy(buffer, result);
        }

        if (send(client_fd, buffer, strlen(buffer)+1, MSG_NOSIGNAL) == -1l) {
            break;
        }
        free(buffer);
    }
    close(client_fd);
    printf("connect has been closed\n");
}

char* get_dns_result(char* buffer) {
    return "mock result";
}

int dns_create_header(struct dns_header *header) {

    if (header == NULL) return -1;
    memset(header, 0, sizeof(struct dns_header));

    //random
    srandom(time(NULL));
    header->id = random();

    header->flags = htons(0x0100);//standard query
    header->questions = htons(1);//only 1 name to query

    return 0;
}

int dns_create_question(struct dns_question* question,const char* hostname){
    if(question==NULL||hostname==NULL) return -1;
    memset(question,0,sizeof(question));
    question->name=calloc(strlen(hostname)+2, sizeof(char));//head & end is to be inserted
    if(question->name==NULL){//如果内存分配失败
        return -2;
    }
    question->length=strlen(hostname)+2;
    question->qtype=htons(1);//to get IPv4 address
    question->qclass=htons(1);//Internet data

    char* qname=question->name;
    char* hostname_dup=strdup(hostname);
	strcpy(hostname + strlen(hostname), ".\0");//just to adapt to the algorythm we used

	int l=0,r=0;
	unsigned char len = 0;
	for (r=0; r<strlen(hostname); ++r) {
		switch (hostname[r]) {
			//handle last token
			case '.': {
				*qname = len;
				qname++;
				//last token
				char* sub = calloc(64, sizeof(char));
				strncpy(sub, hostname+l, len);
				strcpy(qname, sub);
				qname += len;
				len=0;
				//after "."
				l = r+1;
				free(sub);
				break;
			}
			default: {
				len++;
			}
		}
	}

    free(hostname_dup);
	return 0;
}

int dns_build_requestion(struct dns_header* header,struct dns_question* question,char* request,int rlen){
    if(header==NULL||question==NULL||request==NULL) return -1;
    memset(request,0,rlen);

    //header-->request
    memcpy(request,header,sizeof(struct dns_header));//把header的数据 拷贝 到request中
    int offset=sizeof(struct dns_header);

    //question-->request
    memcpy(request+offset,question->name,question->length);//QNAME is not aligned
    offset+=question->length;
    memcpy(request+offset,&question->qtype,sizeof(question->qtype));
    offset+=sizeof(question->qtype);
    memcpy(request+offset,&question->qclass,sizeof(question->qclass));
    offset+=sizeof(question->qclass);
    return offset;
}

int dns_client_commit(const char* domin, char* resp){
    struct hostent* host;
    struct sockaddr_in serv_addr;
    int sockfd=socket(AF_INET,SOCK_DGRAM,0);//pv4, udp;

    if(sockfd<0){//创建失败
        return -1;
    }

    if((host = gethostbyname(server_ip)) == NULL) {//转换为hostent
        perror("gethostbyname");
        exit(1);
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(SERVPORT);
    serv_addr.sin_addr = *((struct in_addr *)host->h_addr);
    bzero(&(serv_addr.sin_zero),8);

    if((connect(sockfd,(struct sockaddr *)&serv_addr,sizeof(struct sockaddr))) == -1) {//发起对服务器的链接
        perror("connect");
        exit(1);
    }

    struct dns_header header={0};
    dns_create_header(&header);
    struct dns_question question={0};
    dns_create_question(&question,domin);

    char* request=calloc(MESSAGE_SIZE, sizeof(char));//假设定义为1024长度
    int length = dns_build_requestion(&header,&question,request,MESSAGE_SIZE);
    char* response = calloc(MESSAGE_SIZE, sizeof(char));

	if (setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
		perror("setsockopt failed");
		return -2;
	}

    send(sockfd, request, length, 0);
    recv(sockfd,response,MESSAGE_SIZE,0);

    if(debug) {
        for(int i=0;i<MESSAGE_SIZE;i++){
            printf("%c",response[i]);
        }
        for(int i=0;i<MESSAGE_SIZE;i++){
            printf("%x",response[i]);
        }
        printf("\n");
    }
	free(request);
	resp = response;
    return 0;
}

int is_pointer(int in) {
	return (in & 0xC0) == 0xC0;
}


void dns_parse_name(unsigned char *chunk, unsigned char *ptr, char *out, int *len) {

	int flag = 0, n = 0, alen = 0;
	char *pos = out + (*len);

	while (1) {

		flag = (int)ptr[0];
		if (flag == 0) break;

		if (is_pointer(flag)) {

			n = (int)ptr[1];
			ptr = chunk + n;
			dns_parse_name(chunk, ptr, out, len);
			break;

		} else {

			ptr ++;
			memcpy(pos, ptr, flag);
			pos += flag;
			ptr += flag;

			*len += flag;
			if ((int)ptr[0] != 0) {
				memcpy(pos, ".", 1);
				pos += 1;
				(*len) += 1;
			}
		}

	}

}

int dns_parse_response(char *buffer, struct dns_item **domains) {

	int i = 0;
	unsigned char *ptr = (unsigned char* )buffer;

	ptr += 4;
	int querys = ntohs(*(unsigned short*)ptr);

	ptr += 2;
	int answers = ntohs(*(unsigned short*)ptr);

	ptr += 6;
	for (i = 0;i < querys;i ++) {
		while (1) {
			int flag = (int)ptr[0];
			ptr += (flag + 1);

			if (flag == 0) break;
		}
		ptr += 4;
	}

	char cname[128], aname[128], ip[20], netip[4];
	int len, type, ttl, datalen;

	int cnt = 0;
	struct dns_item *list = (struct dns_item*)calloc(answers, sizeof(struct dns_item));
	if (list == NULL) {
		return -1;
	}

	for (i = 0;i < answers;i ++) {

		bzero(aname, sizeof(aname));
		len = 0;

		dns_parse_name((unsigned char* )buffer, ptr, aname, &len);
		ptr += 2;

		type = htons(*(unsigned short*)ptr);
		ptr += 4;

		ttl = htons(*(unsigned short*)ptr);
		ptr += 4;

		datalen = ntohs(*(unsigned short*)ptr);
		ptr += 2;

		if (type == DNS_CNAME) {

			bzero(cname, sizeof(cname));
			len = 0;
			dns_parse_name((unsigned char* )buffer, ptr, cname, &len);
			ptr += datalen;

		} else if (type == DNS_HOST) {

			bzero(ip, sizeof(ip));

			if (datalen == 4) {
				memcpy(netip, ptr, datalen);
				inet_ntop(AF_INET , netip , ip , sizeof(struct sockaddr));

				printf("%s has address %s\n" , aname, ip);
				printf("\tTime to live: %d minutes , %d seconds\n", ttl / 60, ttl % 60);

				list[cnt].domain = (char *)calloc(strlen(aname) + 1, 1);
				memcpy(list[cnt].domain, aname, strlen(aname));

				list[cnt].ip = (char *)calloc(strlen(ip) + 1, 1);
				memcpy(list[cnt].ip, ip, strlen(ip));

				cnt ++;
			}

			ptr += datalen;
		}
	}

	*domains = list;
	ptr += 2;

	return cnt;

}





