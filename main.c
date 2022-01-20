#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

#pragma pack(push, 1)
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#pragma pack(pop)
#include <arpa/inet.h>
#include <netinet/in.h>

#include <pcap.h>

#define ETH_HDR_SIZE (sizeof(struct ethhdr))
#define IP_HDR_SIZE (sizeof(struct iphdr))

#define LOG_E(fmt, ...) fprintf(stderr, fmt "\n", ##__VA_ARGS__)
#define LOG_I(fmt, ...) fprintf(stdout, fmt "\n", ##__VA_ARGS__)

struct counters
{
    uint64_t total_pkts;
    uint64_t invalid_pkts;
    uint64_t ip_v4;
    uint64_t udp_pkts;
    uint64_t tcp_pkts;
};

static uint8_t null_buffer[2048];

static void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const uint8_t *pkt_data)
{
    // pkthdr->caplen - size of packet (pkt_data)
    uint32_t inner_size = pkthdr->caplen;
    const uint8_t *inner_data = pkt_data;
    struct counters *stats = (struct counters*) user_data;

    stats->total_pkts++;
    if (inner_size < ETH_HDR_SIZE) {
        stats->invalid_pkts++;
        return;
    }

    const uint16_t l3_proto_type = ntohs(((struct ethhdr *) inner_data)->h_proto);
    if (l3_proto_type != ETH_P_IP)
        return;

    inner_size -= ETH_HDR_SIZE;
    inner_data += ETH_HDR_SIZE;

    // https://datatracker.ietf.org/doc/html/rfc791#section-3.1
    const struct iphdr *iph = (const struct iphdr *) inner_data;
    if (iph->version != 4)
        return;

    const uint16_t ip_hdr_size = iph->ihl * 4;
    if (ip_hdr_size < IP_HDR_SIZE) {
        stats->invalid_pkts++;
        return;
    }

    const uint32_t ip_total_size = ntohs(iph->tot_len) - ip_hdr_size;
    inner_size -= ip_total_size;
    inner_data += ip_total_size;
    stats->ip_v4++;

    switch (iph->protocol) {
        case IPPROTO_UDP:
            stats->udp_pkts++;
        break;
        case IPPROTO_TCP:
            stats->tcp_pkts++;
        break;
    }
    // Эмулирует дальнейшую инспекцию
    memcpy(null_buffer, inner_data, inner_size);
}

int loop(pcap_t *pcap)
{
    int pcap_cnt = 0;
    const int pcap_step = 100;
    struct counters stats = {0};

    while (true) {
        if ((pcap_cnt = pcap_dispatch(pcap, pcap_step, packet_handler, (u_char*) &stats)) < 0) {
            LOG_E("pcap_loop() failed: %s", pcap_geterr(pcap));
            return 1;
        } else if (pcap_cnt < pcap_step)
            break;
    }
    LOG_I("stats { total: %lu invalid: %lu ipv4: %lu udp: %lu tcp: %lu }",
            stats.total_pkts, stats.invalid_pkts, stats.ip_v4, stats.udp_pkts, stats.tcp_pkts);
    return 0;
}

int main(int argc, char* argv[])
{
    pcap_t *pcap = NULL;
    char errbuf[PCAP_ERRBUF_SIZE] = {'\0'};
    int rc = 1;

    if (argc != 2) {
        LOG_E("Usage: %s pcap_file_path", argv[0]);
        goto err;
    }

    pcap = pcap_open_offline(argv[1], errbuf);
    if (pcap == NULL) {
        LOG_E("pcap_open_offline failed: %s", errbuf);
        goto err;
    }

    rc = loop(pcap);
err:
    pcap_close(pcap);
    return rc;
}
