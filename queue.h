#ifndef QUEUE_H
#define QUEUE_H

#include <pcap.h>
#include <pthread.h>

#define QUEUE_SIZE 10000

typedef struct {
    struct pcap_pkthdr header;
    unsigned char *data;
} stored_packet;

typedef struct {
    stored_packet buffer[QUEUE_SIZE];
    int head, tail, count; //индексы начала и конца очереди
    int finished;

    pthread_mutex_t mutex;
    pthread_cond_t cond;
} packet_queue;

typedef struct {
    packet_queue *queue;
    pcap_dumper_t *dumper;
    const char *name;
} thread_arg;

void queue_init(packet_queue *q);
void queue_push(packet_queue *q,
                const struct pcap_pkthdr *header,
                const unsigned char *data);
int  queue_pop(packet_queue *q, stored_packet *pkt);
void queue_finish(packet_queue *q);

void* writer_thread(void *arg);

#endif
