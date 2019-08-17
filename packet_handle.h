#ifndef PACKET_HANDLE_H
#define PACKET_HANDLE_H



#include "packet_detail.h"
#include <stdint.h>
#include <pcap.h>

void get_info(char*,int,Session*);
int get_packet(int size, const uint8_t* packet, Session* session, pcap_t*);
int get_mac_packet(int size, const uint8_t* packet, Session* session, pcap_t* handle);

#endif // PACKET_HANDLE_H
