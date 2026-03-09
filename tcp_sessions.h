#ifndef TCP_SESSIONS_H
#define TCP_SESSIONS_H

#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include "queue.h"

#define MAX_TCP_SESSIONS 1024
#define MAX_SESSION_PACKETS 10000

typedef struct {
    struct in_addr ip1, ip2;
    uint16_t port1, port2;

    int syn_seen, synack_seen, ack_seen;
    int fin1_sent, fin1_acked;
    int fin2_sent, fin2_acked;
    int rst_seen;

    stored_packet packets[MAX_SESSION_PACKETS];
    int packet_count;

    int active;
} tcp_session_t;

void tcp_sessions_init();
void tcp_sessions_process_packet(
    const struct pcap_pkthdr *header,
    const unsigned char *packet,
    const struct iphdr *ip_hdr,
    const struct tcphdr *tcp_hdr,
    packet_queue *output_queue);

#endif
