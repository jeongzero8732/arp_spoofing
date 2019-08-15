#include "packet_detail.h"
#include "packet_header.h"
#include <string.h>
#include <arpa/inet.h>

//extern uint32_t MY_IP;

// make arp_packet
void make_arp_request(Session* session,int num)
{
    /*
        1. check reqeust or reply
        2. check broadcast or multicast
    */

    make_ether_packet(session,num,0);

    for(int i=0; i< session->session_count; i++)
    {
        // 1. arp_reqeust and broadcast

        arp_hdr[i].hardware_type = htons(ETHERNET);
        arp_hdr[i].protocol_type = htons(ARP);
        arp_hdr[i].hardware_size = HARD_SIZE;
        arp_hdr[i].protocol_size = PRO_SIZE;
        arp_hdr[i].opcode=htons(0x0001);

        memcpy(arp_hdr[i].sender_macaddr,ether_hdr[i].eth_src,6);
        memset(arp_hdr[i].target_macaddr,0x00,6);
        arp_hdr[i].sender_ipaddr=MY_IP;
        arp_hdr[i].target_ipaddr=session[i].sender_ip;

        memcpy(&(arp_req[i].eth),ether_hdr,sizeof(ETHER_HDR));
        memcpy(&(arp_req[i].arp),arp_hdr,sizeof(ARP_HDR));
        memcpy(session[i].senderpacket,&(arp_req[i].eth),sizeof(ETHER_HDR));
        memcpy(session[i].senderpacket+sizeof(ETHER_HDR),&(arp_req[i].arp),sizeof(ARP_HDR));
    }



}

void make_arp_reply(Session* session,int num, int index)
{
    make_ether_packet(session,num,index);

    arp_hdr[index].hardware_type = htons(ETHERNET);
    arp_hdr[index].protocol_type = htons(ARP);
    arp_hdr[index].hardware_size = HARD_SIZE;
    arp_hdr[index].protocol_size = PRO_SIZE;
    arp_hdr[index].opcode=htons(0x0002);

    memcpy(arp_hdr[index].sender_macaddr,ether_hdr[index].eth_src,6);
    arp_hdr[index].sender_ipaddr=session[index].target_ip;
    memcpy(arp_hdr[index].target_macaddr,arp_rpy[index].arp.target_macaddr,6);
    arp_hdr[index].target_ipaddr=session[index].sender_ip;

    memcpy(&(arp_rpy[index].eth),&ether_hdr[index],sizeof(ETHER_HDR));
    memcpy(&(arp_rpy[index].arp),&arp_hdr[index],sizeof(ARP_HDR));
    memcpy(session[index].senderpacket,&(arp_rpy[index].eth),sizeof(ETHER_HDR));
    memcpy(session[index].senderpacket+sizeof(ETHER_HDR),&(arp_rpy[index].arp),sizeof(ARP_HDR));

}
