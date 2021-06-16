#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include "header.h"

#define IP_SRC "192.168.52.1"
#define IP_DST "192.168.52.129"

unsigned short checksum(unsigned short *buffer, int size)//置ICMP检验数函数
{
    int checksum = 0;
    while(size>1)
    {
        checksum += *buffer++;
        size -= sizeof(unsigned short);
    }
    if(size){
        checksum += *(unsigned char*)buffer;
    }
    checksum = (checksum>>16) + (checksum & 0xffff);
    checksum += (checksum>>16);
    return (unsigned short)(~checksum);
}

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

    struct sniff_ip *ip = (struct sniff_ip *) buffer;//建立IP数据包整体
    struct sniff_icmp *icmp = (struct sniff_icmp *)(buffer + sizeof(struct sniff_ip));//建立ICMP数据包整体
    //建立源IP和目的IP结构体
    struct in_addr *ip_src = (struct in_addr *)malloc(sizeof(struct in_addr));
    struct in_addr *ip_dst = (struct in_addr *)malloc(sizeof(struct in_addr));
    inet_aton(IP_SRC,ip_src);
    inet_aton(IP_DST,ip_dst);
    //填充ICMP头
    len += sizeof(struct sniff_icmp);
    icmp->icmp_type = 8;
    icmp->icmp_code = 0;
    icmp->icmp_chksum = 0;
    icmp->icmp_id = htons(0x1234);
    icmp->icmp_seq = htons(1);
    icmp->icmp_chksum = checksum((unsigned short *)icmp, sizeof(struct sniff_icmp));  
    //填充IP头
    len += sizeof(struct sniff_ip);
    ip->ip_vhl = 4<<4 | 5;
    ip->ip_tos = 0;
    ip->ip_len = htons(10);
    ip->ip_id = htons(0x1000);
    ip->ip_off = 0;
    ip->ip_ttl = 64;
    ip->ip_p = ICMP_PROTOCOL_NUM;
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