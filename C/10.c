#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include "header.h"

#define IP_SRC "1.2.3.4"
#define IP_DST "192.168.52.129"

int main()
{
    int sd;
    int len = 0;
    struct sockaddr_in sin;
    char buffer[1024];
    //建立通信通道
    sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(sd < 0) 
    {
        perror("socket() error"); 
        exit(-1); 
    }
    sin.sin_family = AF_INET;
	//建立IP数据包整体
    struct sniff_ip *ip = (struct sniff_ip *) buffer;
    //建立源IP和目的IP结构体
    struct in_addr *ip_src = (struct in_addr *)malloc(sizeof(struct in_addr));
    struct in_addr *ip_dst = (struct in_addr *)malloc(sizeof(struct in_addr));
    inet_aton(IP_SRC,ip_src);
    inet_aton(IP_DST,ip_dst);
    //填充IP头
    len += sizeof(struct sniff_ip);
    ip->ip_vhl = 4<<4 | 5;
    ip->ip_tos = 0;
    ip->ip_len = htons(10);
    ip->ip_id = htons(0x1000);
    ip->ip_off = 0;
    ip->ip_ttl = 64;
    ip->ip_p = 4;
    ip->ip_src = *ip_src;
    ip->ip_dst = *ip_dst;
    //发送
    if(sendto(sd, buffer, len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) 
    {
        printf("发送失败\n"); 
		exit(-1); 
    }
    else
    {
        printf("发送成功\n");
    }
}