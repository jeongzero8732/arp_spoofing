#ifndef PACKET_HEADER_H
#define PACKET_HEADER_H

#include <stdint.h>
#define SessionCount 10

#pragma pack(push, 1)
typedef struct ether_header
{
        #define MAC_LEN 6
        uint8_t  eth_dst[6];       //6byte
        uint8_t  eth_src[6];       //6byte
        #define E_ARP 0x0806
        uint16_t eth_type;                      //2byte
}ETHER_HDR;

typedef struct arp_hdr {

    #define ETHERNET 0x0001
        uint16_t hardware_type;

    #define ARP 0x0800
        uint16_t protocol_type;

    #define HARD_SIZE 0x06
        uint8_t hardware_size; //6
    #define PRO_SIZE 0x04
        uint8_t protocol_size; //4

        uint16_t opcode;
        uint8_t sender_macaddr[6];
        uint32_t sender_ipaddr;
        uint8_t target_macaddr[6];
        uint32_t target_ipaddr;
}ARP_HDR;

typedef struct ip_hdr
{
    uint8_t ip_header_len : 4; // 4-bit header length (in 32-bit words) normally=5 (Means 20 Bytes may be 24 also)
    uint8_t ip_version : 4; // 4-bit IPv4 version
    uint8_t ip_tos; // IP type of service
    uint16_t ip_total_length; // Total length
    uint16_t ip_id; // Unique identifier
    uint8_t ip_frag_offset : 5; // Fragment offset field
    uint8_t ip_more_fragment : 1;
    uint8_t ip_dont_fragment : 1;
    uint8_t ip_reserved_zero : 1;
    uint8_t ip_frag_offset1; //fragment offset
    uint8_t ip_ttl; // Time to live
    uint8_t ip_protocol; // Protocol(TCP,UDP etc)
    uint16_t ip_checksum; // IP checksum
    uint32_t ip_srcaddr; // Source address
    uint32_t ip_destaddr; // Source address
} IPV4_HDR;

typedef struct arp_packet
{
    ETHER_HDR eth;
    ARP_HDR arp;
}ARP_PKT;

typedef struct session
{
    int session_count;
    uint32_t sender_ip;
    uint32_t target_ip;
    uint8_t sender_arp_request[42];
    uint8_t sender_arp_reply[42];
    uint8_t find_gateway_mac[42];
}Session;

#pragma pop(1)

extern ETHER_HDR ether_hdr[SessionCount];
extern ARP_HDR arp_hdr[SessionCount];
extern ARP_PKT arp_req[SessionCount];
extern ARP_PKT arp_rpy[SessionCount];
extern ARP_PKT arp_for_mac;

extern uint8_t MY_MAC[6];
extern uint32_t MY_IP;
extern uint8_t gateMac[6];

#endif // PACKET_HEADER_H
