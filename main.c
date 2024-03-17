#include "my_libnet.h"
#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        printf("%u bytes captured\n", header->caplen);

        struct libnet_ethernet_hdr *eth_hdr = (struct libnet_ethernet_hdr*)packet;
        if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) continue; // check IP

        struct libnet_ipv4_hdr *ip_hdr = (struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));
        if (ip_hdr->ip_p != IPPROTO_TCP) continue;// check TCP

        struct libnet_tcp_hdr *tcp_hdr = (struct libnet_tcp_hdr*)(ip_hdr+1);
        struct libnet_tcp_data *tcp_data = (struct libnet_tcp_data*)(tcp_hdr+1);
        printf("##### ETHERNET HDR #####\n");
        printf("  SRC MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", eth_hdr->ether_shost[0]
               , eth_hdr->ether_shost[1], eth_hdr->ether_shost[2]
               , eth_hdr->ether_shost[3], eth_hdr->ether_shost[4]
               , eth_hdr->ether_shost[5]);
        printf("  DST MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", eth_hdr->ether_dhost[0]
               , eth_hdr->ether_dhost[1], eth_hdr->ether_dhost[2]
               , eth_hdr->ether_dhost[3], eth_hdr->ether_dhost[4]
               , eth_hdr->ether_dhost[5]);
        printf("##### NETWORK HDR #####\n");
        char str_ip_addr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_hdr->ip_src), str_ip_addr, INET_ADDRSTRLEN);
        printf("  SRC IP: %s\n", str_ip_addr);
        inet_ntop(AF_INET, &(ip_hdr->ip_dst), str_ip_addr, INET_ADDRSTRLEN);
        printf("  DST IP: %s\n", str_ip_addr);
        printf("##### TRANSPORT HDR #####\n");
        printf("  SRC PORT: %hu\n", ntohs(tcp_hdr->th_sport));
        printf("  DST PORT: %hu\n", ntohs(tcp_hdr->th_dport));
        printf("##### APPLICATION HDR #####\n");
        for(int i=0;i<10;i++){
            printf("%02hhx ", tcp_data->data[i]);
        }
        printf("\n\n");
    }

    pcap_close(pcap);
}
