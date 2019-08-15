#ifndef MY_INFO_H
#define MY_INFO_H
#include "packet_header.h"


void my_mac(char*);
void my_ip(char*);
void make_ether_packet(Session*, int, int);
void make_arp_packet(Session* session,int,int);
#endif // MY_INFO_H
