#pragma once

#include <netdb.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "packet_header.h"
#include "make_packet.h"
#include "packet_handle.h"


uint8_t MY_MAC[6];
uint32_t MY_IP;

void my_mac(char* device)
{
    int i;
    int fd;
    struct ifreq ifr;
    char* iface=device;
    uint8_t* mac=NULL;

    memset(&ifr, 0, sizeof(ifr));

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name , iface , IFNAMSIZ-1);

    if (0 == ioctl(fd, SIOCGIFHWADDR, &ifr))
    {
        mac = (uint8_t*)ifr.ifr_hwaddr.sa_data;
    }

    memcpy(MY_MAC,mac, 6);

    //for debuging
    //printf("%x %x %x %x %x %x\n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);

    close(fd);
}

void my_ip(char* device)
{
    int n;
    struct ifreq ifr;
    char* array=device;
    char* buf=NULL;

    n = socket(AF_INET, SOCK_DGRAM, 0);
    //Type of address to retrieve - IPv4 IP address
    ifr.ifr_addr.sa_family = AF_INET;
    //Copy the interface name in the ifreq structure
    strncpy(ifr.ifr_name , array , IFNAMSIZ - 1);
    ioctl(n, SIOCGIFADDR, &ifr);
    close(n);

    //display result
    //printf("IP Address is %s - %s\n" , array , inet_ntoa(( (struct sockaddr_in *)&ifr.ifr_addr )->sin_addr) );

   // printf("%x %x %x %x",buf[0],buf[1],buf[2],buf[3],buf[4]);
    MY_IP=(uint32_t)(inet_addr(inet_ntoa(( (struct sockaddr_in *)&ifr.ifr_addr )->sin_addr)));

}

void gate_mac(Session* session)
{
     make_ether_packet(session,0,0);

     arp_hdr->hardware_type = htons(ETHERNET);
     arp_hdr->protocol_type = htons(ARP);
     arp_hdr->hardware_size = HARD_SIZE;
     arp_hdr->protocol_size = PRO_SIZE;
     arp_hdr->opcode=htons(0x0001);

     memcpy(arp_hdr->sender_macaddr,ether_hdr->eth_src,6);
     memset(arp_hdr->target_macaddr,0x00,6);
     arp_hdr->sender_ipaddr=MY_IP;
     arp_hdr->target_ipaddr=session->target_ip;

     memcpy(&(arp_req->eth),ether_hdr,sizeof(ETHER_HDR));
     memcpy(&(arp_req->arp),arp_hdr,sizeof(ARP_HDR));
     memcpy(session->find_gateway_mac,&(arp_req->eth),sizeof(ETHER_HDR));
     memcpy(session->find_gateway_mac+sizeof(ETHER_HDR),&(arp_req->arp),sizeof(ARP_HDR));
}
void make_ether_packet(Session* session, int num, int index)
{
    uint8_t broad[6];

    if(num==0) //for find gateway mac
    {
        memset(broad,0xff,6);
        memcpy(ether_hdr->eth_src,MY_MAC,6);
        memcpy(ether_hdr->eth_dst,broad,6);
        ether_hdr->eth_type=htons(E_ARP);
    }
    else if(num == 1 ) // for find target mac
    {
        for(int i=0;i< session->session_count; i++)
        {
            memset(broad,0xff,6);
            memcpy(ether_hdr[i].eth_src,MY_MAC,6);
            memcpy(ether_hdr[i].eth_dst,broad,6);
            ether_hdr[i].eth_type=htons(E_ARP);
        }
    }
    else if(num ==3) // for make reply pky
    {
        memcpy(ether_hdr[index].eth_src,MY_MAC,6);
        memcpy(ether_hdr[index].eth_dst,arp_rpy[index].arp.target_macaddr,6);
        ether_hdr[index].eth_type=htons(E_ARP);
    }


}

void make_arp_packet(Session* session,int num, int index)
{
    switch(num)
    {
        case 1:
        make_arp_request(session,num);
        break;
        case 2:
        break;
        case 3:
        make_arp_reply(session,num,index);
        break;
        default:
        break;
    }

}

