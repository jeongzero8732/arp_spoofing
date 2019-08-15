#ifndef MAKE_PAKCET_H
#define MAKE_PAKCET_H
#include "packet_header.h"

void make_arp_request(Session*,int);
void make_arp_request_multicast(char*, char*);
void make_arp_reply(Session*, int, int);

#endif // MAKE_PAKCET_H
