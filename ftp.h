#ifndef FTP_H
#define FTP_H

#include <netinet/in.h>
#include <pcap.h>
#include "queue.h"

void ftp_init();
int ftp_is_control(int src_port, int dst_port);
int ftp_is_data(int src_port, int dst_port);

void ftp_handle_control(
    struct in_addr src,
    struct in_addr dst,
    int src_port,
    int dst_port,
    const unsigned char *payload,
    int payload_len,
    const struct pcap_pkthdr *header,
    const unsigned char *packet,
    packet_queue *q_control);

void ftp_handle_data(
    struct in_addr src,
    struct in_addr dst,
    int src_port,
    int dst_port,
    const struct pcap_pkthdr *header,
    const unsigned char *packet,
    packet_queue *q_data);

#endif
