#ifndef PROCESS_H
#define PROCESS_H

#include <pcap.h>

void process_packet(const struct pcap_pkthdr *header,
                    const unsigned char *packet,
                    pcap_dumper_t *dumper_h1,
                    pcap_dumper_t *dumper_h2,
                    pcap_dumper_t *dumper_h3,
                    pcap_dumper_t *dumper_h4);

void process_pcap_file(const char *filepath);
void process_directory(const char *dirpath);

#endif
