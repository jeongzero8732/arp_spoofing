#include <stdio.h>
#include <pcap.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdlib.h>
#include <unistd.h>

#include <packet_header.h>
#include <packet_handle.h>


ETHER_HDR ether_hdr[SessionCount];
ARP_HDR arp_hdr[SessionCount];
ARP_PKT arp_req[SessionCount];
ARP_PKT arp_rpy[SessionCount];
ARP_PKT arp_for_mac;

IPV4_HDR* ip_pkt;

void usage() {
  printf("syntax: pcap_test <interface> <sender_ip> <target_ip> \n");
  printf("sample: pcap_test wlan0 1.1.1.1 2.2.2.2\n");
}

int main(int argc, char** argv)
{
    if (argc < 3)
    {
      usage();
      return -1;
    }

    int num,k;
    int tmp=0;
    char* dev=argv[1];
    pcap_t* handle;
    pcap_t* handle2;
    char errbuf[PCAP_ERRBUF_SIZE];


    printf("insert session count : ");
    scanf("%d",&num);
    puts("---------------------------------------------------------------");

    Session session[num];

    //sessio_ip store
    for(int i=0; i<num; i++)
    {
        session[i].sender_ip=inet_addr(argv[i*2+2]);
        session[i].target_ip=inet_addr(argv[i*2+3]);
        session[i].session_count=num;
        memset(session[i].sender_arp_request,0x00,sizeof(session[i].sender_arp_request));
        memset(session[i].sender_arp_reply,0x00,sizeof(session[i].sender_arp_reply));

    }

    get_info(dev,1,session); //my mac
    get_info(dev,2,session); //my ip
    get_info(dev,3,session); //gate mac

    if ((handle = pcap_open_live(dev, BUFSIZ,1, 1, errbuf))==NULL)
    {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    //send arp for find_gate_mac
    if (pcap_sendpacket(handle, session->find_gateway_mac, sizeof(ARP_PKT) /* size */ ) != 0 )
    {
        fprintf(stderr,"=================find gateway mac================\n");

        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(handle));
        return -1;
    }

    while (true)
    {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
       // printf("%u bytes captured\n", header->caplen);
        if(get_mac_packet(header->len, packet, session,handle)==1)
            break;
    }

    pcap_close(handle);

    if ((handle2 = pcap_open_live(dev, BUFSIZ,1, 1, errbuf))==NULL)
    {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    //make arp_request pkts
    make_arp_packet(session,1,0);

    //arp reqeust
    for(int i=0; i<session->session_count; i++)
    {
        printf("send arp request to find target mac!!\n");
        if (pcap_sendpacket(handle2, session[i].sender_arp_request, sizeof(ARP_PKT) /* size */ ) != 0 )
        {
            fprintf(stderr,"=================arp request for target mac================\n");

            fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(handle));
            return -1;
        }

        printf("send arp request to find target mac!!\n");
        if (pcap_sendpacket(handle2, session[i].sender_arp_request, sizeof(ARP_PKT) /* size */ ) != 0 )
        {
            fprintf(stderr,"=================arp request for target mac================\n");

            fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(handle));
            return -1;
        }

    }

    //find target_mac
    while (true)
    {
        k++;
        struct pcap_pkthdr* header2;
        const u_char* packet2;
        int res2 = pcap_next_ex(handle2, &header2, &packet2);
        if (res2 == 0) continue;
        if (res2 == -1 || res2 == -2) break;
       // printf("%u bytes captured\n", header->caplen);
        get_packet(header2->len, packet2, session,handle2);
        printf("k\n");
    }

    pcap_close(handle2);

    return 0;
}
