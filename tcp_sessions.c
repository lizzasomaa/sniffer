#include "tcp_sessions.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static tcp_session_t sessions[MAX_TCP_SESSIONS];

static tcp_session_t* get_session(struct in_addr src, struct in_addr dst,
                                  uint16_t sport, uint16_t dport)
{
    for (int i = 0; i < MAX_TCP_SESSIONS; i++) {
        if (!sessions[i].active) continue;

        //сессия уже сохранена
        if ((sessions[i].ip1.s_addr == src.s_addr &&
             sessions[i].ip2.s_addr == dst.s_addr &&
             sessions[i].port1 == sport &&
             sessions[i].port2 == dport) ||

            (sessions[i].ip1.s_addr == dst.s_addr &&
             sessions[i].ip2.s_addr == src.s_addr &&
             sessions[i].port1 == dport &&
             sessions[i].port2 == sport))
            return &sessions[i];
    }

    //сохраняем новую сессию
    for (int i = 0; i < MAX_TCP_SESSIONS; i++) {
        if (!sessions[i].active) {
            sessions[i].active = 1;
            sessions[i].ip1 = src;
            sessions[i].ip2 = dst;
            sessions[i].port1 = sport;
            sessions[i].port2 = dport;
            return &sessions[i];
        }
    }
    return NULL;
}

static void store_packet(tcp_session_t *s,
                         const struct pcap_pkthdr *header,
                         const unsigned char *packet)
{
    if (s->packet_count >= MAX_SESSION_PACKETS) return;

    s->packets[s->packet_count].header = *header;
    s->packets[s->packet_count].data = malloc(header->caplen);
    memcpy(s->packets[s->packet_count].data, packet, header->caplen);
    s->packet_count++;
}

static void reset_session(tcp_session_t *s)
{
    for (int i = 0; i < s->packet_count; i++) {
        free(s->packets[i].data);
    }
    memset(s, 0, sizeof(*s));
}

static void dump_session(tcp_session_t *s, packet_queue *q)
{
    /*printf("[H3 TCP COMPLETE SESSION] %s:%d <-> %s:%d packets: %d\n",
           inet_ntoa(s->ip1), s->port1,
           inet_ntoa(s->ip2), s->port2,
           s->packet_count);*/

    for (int i = 0; i < s->packet_count; i++) {
        queue_push(q, &s->packets[i].header, s->packets[i].data);
        free(s->packets[i].data);
    }
    s->packet_count = 0;
}

void tcp_sessions_process_packet(
    const struct pcap_pkthdr *header,
    const unsigned char *packet,
    const struct iphdr *ip_hdr,
    const struct tcphdr *tcp_hdr,
    packet_queue *output_queue)
{
    struct in_addr src, dst;
    src.s_addr = ip_hdr->saddr;
    dst.s_addr = ip_hdr->daddr;

    uint16_t sport = ntohs(tcp_hdr->source);
    uint16_t dport = ntohs(tcp_hdr->dest);

    tcp_session_t *s = get_session(src, dst, sport, dport);
    if (!s) return;

    //определяем отправителя
    int from_ip1 = (s->ip1.s_addr == src.s_addr && s->port1 == sport);

    store_packet(s, header, packet);

    //RSR
    if (tcp_hdr->rst) {
        reset_session(s);
        return;
    }

    //трехстороннее рукопожатие
    if (tcp_hdr->syn && !tcp_hdr->ack) s->syn_seen = 1;
    if (tcp_hdr->syn && tcp_hdr->ack)  s->synack_seen = 1;
    if (!tcp_hdr->syn && tcp_hdr->ack) s->ack_seen = 1;

    //получение FIN
    if (tcp_hdr->fin) {
        if (from_ip1) s->fin1_sent = 1;
        else s->fin2_sent = 1;
    }

    //получение подтверждения на FIN
    if (tcp_hdr->ack) {
        if (!from_ip1 && s->fin1_sent) s->fin1_acked = 1;
        if (from_ip1 && s->fin2_sent)  s->fin2_acked = 1;
    }

    if (s->syn_seen && s->synack_seen && s->ack_seen &&
        s->fin1_sent && s->fin2_sent &&
        s->fin1_acked && s->fin2_acked &&
        !s->rst_seen)
    {
        dump_session(s, output_queue);
        reset_session(s);
    }
}
