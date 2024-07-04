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
#define DNS_IP 0x01
#define BUCKET_SIZE 1<<15//size of our map
#define DEFAULT_FILENAME "dnsrelay.txt"
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
struct entry {
	char domain_name[255];
	char ip[16];
	struct entry* next;
};

//method declare
void handle_request(void* client_fd_addr);
char* get_dns_result(char* buffer);
int dns_create_header(struct dns_header *header);
int dns_create_question(struct dns_question* question,const char* hostname);
int dns_build_requestion(struct dns_header* header,struct dns_question* question,char* request,int rlen);
int dns_client_commit(const char* domin, char* resp);
void dns_parse_name(unsigned char *ptr, char *out);
int dns_parse_response(char *buffer);
char* get(char* domain_name);
int put(char* domain_name, char* ip);

//global varieble
char* server_ip = NULL;
int debug = 0;
int ttl=64;
char* filename=NULL;
struct entry* map = NULL;
int main(int argc,char *argv[]) {
    struct sockaddr_in server_sockaddr,client_sockaddr;//声明服务器和客户端的socket存储结构
    socklen_t sin_size;
    int sockfd,client_fd;//socket描述符
    server_ip = calloc(30, sizeof(char));
	filename=calloc(100, sizeof(char));
	strcpy(server_ip, DEFAULT_SERVER_IP);
	strcpy(filename, DEFAULT_FILENAME);
	map = calloc(BUCKET_SIZE, sizeof(struct entry));

	//execute command
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
                	case 'f':{
						strcpy(filename, pchar);
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

	if(debug) {
		printf("reading file\n");
	}


	FILE* file = fopen(filename, "r");
	if (file == NULL) {
		perror("Error opening file");
		exit(1);
	}

	char* ip=calloc(16, sizeof(char));
	char* domain=calloc(255, sizeof(char));

	int f=fscanf(file, "%s %s", ip, domain);
	while (f!=EOF && f == 2) {
        put(domain, ip);
		if (debug) {
			printf("use domain %s get from map:%s\n",domain,get(domain));
		}
		bzero(ip, 16);
		bzero(domain,255);
		f=fscanf(file, "%s %s", ip, domain);
	}

	fclose(file);
	free(filename);
	free(ip);
	free(domain);

	if (debug) {
		printf("start working\n");
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
        char* result = get(buffer);
        if(result == NULL) {
        	if (debug) {
        		printf("failed to find ip in map, sending to server\n");
        	}
        	char* response=calloc(MESSAGE_SIZE, sizeof(char));
            int res = dns_client_commit(buffer, response);
        	if (res != 0) {
				strcpy(buffer, "domain name dealing failed!");
        	}
        	dns_parse_response(response);
        	if(debug) {
        		for(int i=0;i<MESSAGE_SIZE;i++){
        			printf("%c",response[i]);
        		}
        		for(int i=0;i<MESSAGE_SIZE;i++){
        			printf("%x",response[i]);
        		}
        		printf("\n");
        	}
        }else if (strcmp(result, "0.0.0.0") == 0) {
            strcpy(buffer, "Bad domain name! Do not access!");
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

unsigned hash(char* str) {
	int n = strlen(str);
	unsigned int hashValue = 0;

	for (int i = 0; i < n; i++) {
		hashValue = hashValue * 31 + str[i];
	}

	return hashValue;
}

char* get(char* domain_name) {
	if (domain_name == NULL) {
		if (debug) {
			printf("null pointer exception in get!\n");
		}
		return -1;
	}
	unsigned index = hash(domain_name) & (BUCKET_SIZE-1);
	if (strlen(map[index].ip)==0) {
		return NULL;
	}
	struct entry* e = &map[index];
	while (e!=NULL && strcmp(e->domain_name, domain_name)!=0) {
		e = e->next;
	}
	return e==NULL?NULL : e->ip;

}
int put(char* domain_name, char* ip) {
	if (domain_name == NULL || ip==NULL) {
		if (debug) {
			printf("null pointer exception in put!");
		}
		return -1;
	}
	unsigned index = hash(domain_name) & (BUCKET_SIZE-1);
	//empty bucket
	if (strlen(map[index].ip)==0) {
		struct entry* e = calloc(1, sizeof(struct entry));
		strcpy(e->domain_name, domain_name);
		strcpy(e->ip, ip);
		map[index] = *e;
		free(e);
		return 0;
	}
	struct entry* e = &map[index], *pre=e;
	//find end or cover
	while (e!=NULL && strcmp(e->domain_name, domain_name)!=0) {
		pre = e;
		e = e->next;
	}
	struct entry* cur;
	if (e==NULL) {
		cur = pre->next=calloc(1, sizeof(struct entry));
	}else {
		cur = e;
	}
	strcpy(cur->domain_name, domain_name);
	strcpy(cur->ip, ip);
	return 0;
}


int dns_create_header(struct dns_header *header) {
	if (debug) {
		printf("dns_create_header begin!\n");
	}
    if (header == NULL) return -1;
    memset(header, 0, sizeof(struct dns_header));

    //random
    srandom(time(NULL));
    header->id = random();

    header->flags = htons(0x0100);//standard query
    header->questions = htons(1);//only 1 name to query
	if (debug) {
		printf("dns_create_header end!\n");
	}
    return 0;
}

int dns_create_question(struct dns_question* question,const char* hostname){
	if (debug) {
		printf("dns_create_question begin!\n");
	}
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
	if (debug) {
		printf("dns_create_question end!\n");
	}
	return 0;
}

int dns_build_requestion(struct dns_header* header,struct dns_question* question,char* request,int rlen){
	if (debug) {
		printf("dns_build_requestion begin!\n");
	}
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
	if (debug) {
		printf("dns request\n");
		for(int i=0;i<30;i++){
			printf("%x",request[i]);
		}
		printf("dns_build_requestion end!\n");
	}
    return offset;
}

int dns_client_commit(const char* domin, char* resp){
	if (debug) {
		printf("dns_client_commit begin!\n");
	}
    struct hostent* host;
    struct sockaddr_in serv_addr;
    int sockfd=socket(AF_INET,SOCK_DGRAM,0);//pv4, udp;

    if(sockfd<0){//创建失败
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(SERVPORT);
	if (inet_pton(AF_INET, server_ip, &(serv_addr.sin_addr)) != 1) {
		perror("setting ip");
		return -2;
	}
    bzero(&(serv_addr.sin_zero),8);

    if((connect(sockfd,(struct sockaddr *)&serv_addr,sizeof(struct sockaddr))) == -1) {//发起对服务器的链接
        perror("connect");
    	return -3;
    }

    struct dns_header header={0};
    dns_create_header(&header);
    struct dns_question question={0};
    dns_create_question(&question,domin);

    char* request=calloc(MESSAGE_SIZE, sizeof(char));//假设定义为1024长度
    int length = dns_build_requestion(&header,&question,request,MESSAGE_SIZE);
    char* response = calloc(MESSAGE_SIZE, sizeof(char));

	if (setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
		perror("setsockopt-ttl failed");
		return -4;
	}

    int res = send(sockfd, request, length, MSG_NOSIGNAL);
    recv(sockfd,response,MESSAGE_SIZE,MSG_NOSIGNAL);
	strcpy(resp, response);
	free(request);
    return -res;
}

void dns_parse_name(unsigned char *ptr, char *out) {

	int i=0, len=0;
	while ((len=ptr[i])!=0) {
		strncpy(out+i, &ptr[i+1], len);
		i += (len+1);
	}
}

int dns_parse_response(char *buffer) {

	int i = 0;
	unsigned char *ptr = (unsigned char* )buffer;

	ptr += 4;
	int querys = ntohs(*(unsigned short*)ptr);

	ptr += 2;
	int answers = ntohs(*(unsigned short*)ptr);

	//questions
	ptr += 6;
	for (i = 0;i < querys;i ++) {
		while (1) {
			//3www5baidu3com0
			int flag = ptr[0];
			ptr += (flag + 1);

			if (flag == 0) break;
		}
		ptr += 4;
	}

	//answers
	char aname[128], ip[20], netip[4];
	int type, datalen;

	int cnt = 0;
	struct dns_item *list = calloc(answers, sizeof(struct dns_item));
	if (list == NULL) {
		return -1;
	}

	for (i = 0;i < answers;i ++) {

		bzero(aname, sizeof(aname));

		dns_parse_name(ptr, aname);
		ptr += (strlen(ptr)+1);

		type = htons(*(unsigned short*)ptr);
		ptr += 8;

		datalen = ntohs(*(unsigned short*)ptr);
		ptr += 2;

		//we only accept IPv4
		if(type!=DNS_IP || datalen!=4) {
			continue;
		}

		memcpy(netip, ptr, datalen);
		inet_ntop(AF_INET , netip , ip , sizeof(struct sockaddr));

		put(buffer, ip);

		++cnt;
	}
	return cnt;
}





