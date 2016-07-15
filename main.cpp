#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <pcap/pcap.h>
#include <libnet.h>

#define IP_TCP 0x06
#define IP_UDP 0x11

pcap_t *pif;

 const char *get_ip_type_descr(uint8_t ip_typ) {
    switch (ip_typ) {
    case IP_TCP: return "TCP";
    case IP_UDP: return "UDP";
    default: return NULL;
    }
 }

 const char *repr_mac_addr(const uint8_t macaddr[6]) {
    static char repr_str[32];
    snprintf(repr_str, 32, "%02x:%02x:%02x:%02x:%02x:%02x", macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4], macaddr[5]);
    return repr_str;
 }


 void show_help_die (const char *progname) {
    fprintf(stderr, "Usage: %s [-i iface]\n", progname);
    exit(EXIT_FAILURE);
 }


 inline uint32_t readnetu32(const uint32_t *ptr) {
    const uint8_t *const bptr = (const uint8_t *const)ptr;
    return ((uint32_t)bptr[0] << 24) | ((uint32_t)bptr[1] << 16) | ((uint32_t)bptr[2] << 8) | (uint32_t)bptr[3];
 }


 inline uint16_t readnetu16(const uint16_t *ptr) {
    const uint8_t *const bptr = (const uint8_t *const)ptr;
    return ((uint16_t)bptr[0] << 8) | (uint16_t)bptr[1];
 }


 void my_handler (u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    const struct libnet_ethernet_hdr *eth_hdr;
    uint16_t eth_typ;

    eth_hdr = (const struct libnet_ethernet_hdr *)bytes;
    printf(" src.mac = %17s\n", repr_mac_addr(eth_hdr->ether_shost));
    printf(" dst.mac = %17s\n", repr_mac_addr(eth_hdr->ether_dhost));
    eth_typ = readnetu16(&eth_hdr->ether_type);

    if (eth_typ == ETHERTYPE_IP) {
        if (h->caplen < 14 + 20) {
            printf(" <malf/trunc IPv4 hdr>\n");
            fflush(stdout);
            return;
        } else {
            const struct libnet_ipv4_hdr *ip_pkt = (const struct libnet_ipv4_hdr *)(bytes + 14);
            const unsigned int iphdr_len = ip_pkt->ip_hl * 4;
            const uint8_t *ip_payload;
            uint32_t src_addr, dst_addr;
            src_addr = readnetu32(&ip_pkt->ip_src.s_addr);
            dst_addr = readnetu32(&ip_pkt->ip_dst.s_addr);
            printf(" src.ip = %u.%u.%u.%u\n dst.ip = %u.%u.%u.%u\n",
                    (src_addr >> 24) & 0xff, (src_addr >> 16) & 0xff, (src_addr >> 8) & 0xff, src_addr & 0xff,
                    (dst_addr >> 24) & 0xff, (dst_addr >> 16) & 0xff, (dst_addr >> 8) & 0xff, dst_addr & 0xff);

            ip_payload = ((uint8_t *)ip_pkt) + iphdr_len;
            switch (ip_pkt->ip_p) {
            case IP_TCP:
                if (h->caplen < 14 + iphdr_len + 20) {
                    printf(" <malf/trunc TCP hdr>\n");
                    fflush(stdout);
                    return;
                } else {
                    const struct libnet_tcp_hdr *tcp_hdr = ((const struct libnet_tcp_hdr *)ip_payload);
                    printf(" src.port = %u\n dst.port = %u\n",
                        readnetu16(&tcp_hdr->th_sport), readnetu16(&tcp_hdr->th_dport));
                }
                break;
            case IP_UDP:
                if (h->caplen < 14 + iphdr_len + 8) {
                    printf(" <malf/trunc UDP hdr>\n");
                    fflush(stdout);
                    return;
                } else {
                    const struct libnet_udp_hdr *udp_hdr = ((const struct libnet_udp_hdr *)ip_payload);
                    printf(" src.port = %u\n dst.port = %u\n", readnetu16(&udp_hdr->uh_sport), readnetu16(&udp_hdr->uh_dport));

                }
                break;
            }
        }
    }

    puts("");
    fflush(stdout);
 }


 void on_signal (int sig) {
    if (pif) pcap_close(pif);
    exit(128 + sig);
 }


 int main (int argc, char **argv) {
    int opt, err;
    enum { SRC_INVAL, SRC_IFACE, SRC_FILE } pcap_src = SRC_INVAL;
    const char *src_name = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct sigaction sig_exit = {{on_signal}};


    if (sigaction(SIGINT, &sig_exit, NULL) < 0 ||
            sigaction(SIGTERM, &sig_exit, NULL) < 0) {
        perror("sigaction");
        return EXIT_FAILURE;
    }


    while ((opt = getopt(argc, argv, "?hi:r:")) != -1) {
        if (opt == '?' || opt == 'h') {
            show_help_die(argv[0]);
        } else if (!(opt == 'i' || opt == 'r')) {
            fprintf(stderr, "%s: invalid option -- '%c'\n", argv[0], opt);
            show_help_die(argv[0]);
        } else if (pcap_src != SRC_INVAL) {
            fprintf(stderr, "%s: duplicate option -- '%c'\n", argv[0], opt);
            show_help_die(argv[0]);
        } else {
            pcap_src = (opt == 'i' ? SRC_IFACE : SRC_FILE);
            src_name = optarg;
        }
    }

    if (pcap_src == SRC_INVAL || optind < argc)
        show_help_die(argv[0]);


    if (pcap_src == SRC_IFACE)
        pif = pcap_open_live(src_name, 16384, 1, 100, errbuf);
    else
        pif = pcap_open_offline(src_name, errbuf);


    if (pif == NULL) {
        fprintf(stderr, "pcap_open: %s\n", errbuf);
        return EXIT_FAILURE;
    }


    if (pcap_set_datalink(pif, DLT_EN10MB) < 0) {
        pcap_perror(pif, "pcap_set_datalink");
        pcap_close(pif);
        return EXIT_FAILURE;
    }


    err = pcap_loop(pif, -1, my_handler, NULL);
    if (err == -1)
        pcap_perror(pif, "pcap_loop");


    pcap_close(pif);
    pif = NULL;


    return err < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
