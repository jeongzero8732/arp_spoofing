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

    int num;
    char* dev=argv[1];
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    printf("insert session count : ");
    scanf("%d",&num);


    Session session[num];
    get_info(dev,1); //my mac
    get_info(dev,2); //my ip

    //sessio_ip store
    for(int i=0; i<num; i++)
    {
        session[i].sender_ip=inet_addr(argv[argc-2]);
        session[i].target_ip=inet_addr(argv[argc-1]);
        session[i].session_count=num;
    }
    printf("@@@@% x \n",session[0].sender_ip);

    if ((handle = pcap_open_live(dev, BUFSIZ,1, 1, errbuf))==NULL)
    {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    //make arp_request pkts
    make_arp_packet(session,1,0);

    //arp reqeust
    for(int i=0; i<session->session_count; i++)
    {
        if (pcap_sendpacket(handle, session[i].senderpacket, sizeof(ARP_PKT) /* size */ ) != 0 )
        {
            fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(handle));
            return -1;
        }
    }

    //find target_mac
    while (true)
    {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        printf("%u bytes captured\n", header->caplen);
        get_packet(header->len, packet, session,handle);
    }

    pcap_close(handle);

    return 0;
}
