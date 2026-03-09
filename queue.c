#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "queue.h"

void queue_init(packet_queue *q) {
    q->head = q->tail = q->count = 0;
    q->finished = 0;
    pthread_mutex_init(&q->mutex, NULL);
    pthread_cond_init(&q->cond, NULL);
}

void queue_push(packet_queue *q,
                const struct pcap_pkthdr *header,
                const unsigned char *data)
{
    //захват мьютекса
    pthread_mutex_lock(&q->mutex);

    if (q->count >= QUEUE_SIZE) {
        pthread_mutex_unlock(&q->mutex);
        return;
    }

    //сохраняем пакет в буфер
    stored_packet *pkt = &q->buffer[q->tail];
    pkt->header = *header;
    pkt->data = malloc(header->caplen);
    memcpy(pkt->data, data, header->caplen);

    //меняем конец очереди
    q->tail = (q->tail + 1) % QUEUE_SIZE;
    q->count++;

    //освобождаем мьютекс
    pthread_cond_signal(&q->cond);
    pthread_mutex_unlock(&q->mutex);
}

int queue_pop(packet_queue *q, stored_packet *pkt)
{
    //захват мьютекса
    pthread_mutex_lock(&q->mutex);

    //очередь пуста и не все данные обработаны
    while (q->count == 0 && !q->finished) pthread_cond_wait(&q->cond, &q->mutex);

    //очередь пуста и все обработано
    if (q->count == 0 && q->finished) {
        pthread_mutex_unlock(&q->mutex);
        return 0;
    }

    //забираем пакет, меняем начало очереди
    *pkt = q->buffer[q->head];
    q->head = (q->head + 1) % QUEUE_SIZE;
    q->count--;

    pthread_mutex_unlock(&q->mutex);
    return 1;
}

void queue_finish(packet_queue *q)
{
    pthread_mutex_lock(&q->mutex);
    q->finished = 1;
    pthread_cond_signal(&q->cond);
    pthread_mutex_unlock(&q->mutex);
}

void* writer_thread(void *arg)
{
    thread_arg *t = (thread_arg*)arg;
    stored_packet pkt;

    //вытаскиваем все из очереди
    while (queue_pop(t->queue, &pkt)) {
        pcap_dump((unsigned char*)t->dumper, &pkt.header, pkt.data);
        free(pkt.data);
    }

    return NULL;
}
