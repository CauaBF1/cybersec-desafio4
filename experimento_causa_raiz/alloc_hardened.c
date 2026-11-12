/*
 * alloc_hardened.c -- derivado didatico de pwnymalloc/challenge/alloc.c.
 *
 * Duas variantes no mesmo arquivo:
 *
 *   (padrao)                  -> PREV_INUSE + validacao do boundary tag.
 *   -DPWN_BTAG_CHECK_ONLY     -> apenas a validacao do boundary tag.
 *
 * A segunda variante e o controle do experimento: ela bloqueia o payload
 * original, mas continua contornavel porque header e footer falsos estao
 * ambos em memoria controlada pelo atacante. A primeira variante acrescenta
 * o estado confiavel (PREV_INUSE) que o allocator original nao tem.
 *
 * A API publica e o printf("Block size: ...") sao mantidos de proposito:
 * o exploit e o harness dependem deles.
 */

#include <unistd.h>
#include <stdio.h>
#include <stdint.h>

#include "alloc.h"

typedef struct chunk_meta {
    size_t size;
    struct chunk_meta *next; // only for free blocks
    struct chunk_meta *prev; // only for free blocks
} chunk_meta_t;

typedef struct btag { // only for free blocks
    size_t size;
} btag_t;

typedef chunk_meta_t *chunk_ptr;

#define ALIGNMENT 16
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))
#define MAX(x, y) ((x) > (y) ? (x) : (y))

#define INUSE_META_SIZE (sizeof(chunk_meta_t) - 2 * sizeof(chunk_meta_t *))
#define FREE_META_SIZE sizeof(chunk_meta_t)
#define BTAG_SIZE sizeof(btag_t)
#define MIN_BLOCK_SIZE (FREE_META_SIZE + BTAG_SIZE)

#define FREE 0
#define INUSE 1

/* Bit 1 do header: o chunk anterior esta em uso (logo, nao tem footer). */
#define PREV_INUSE 2

/* Tamanhos sao multiplos de 16; os bits baixos ficam para os flags. */
#define SIZE_MASK (~(size_t)(ALIGNMENT - 1))

#ifdef PWN_BTAG_CHECK_ONLY
#define HAS_PREV_INUSE 0
#else
#define HAS_PREV_INUSE 1
#endif

#ifdef PWN_DEBUG
#define BTAG_LOG(...) fprintf(stderr, "[pwnymalloc] " __VA_ARGS__)
#else
#define BTAG_LOG(...) ((void)0)
#endif

static size_t make_header(size_t size, int status, int prev_inuse);
static size_t get_size(chunk_ptr block);
static size_t get_prev_size(chunk_ptr block);
static void set_btag(chunk_ptr block, size_t size);
static int get_status(chunk_ptr block);
static void set_status(chunk_ptr block, int status);
static int get_prev_inuse(chunk_ptr block);
static void set_prev_inuse(chunk_ptr block, int value);
static chunk_ptr next_chunk(chunk_ptr block);
static chunk_ptr prev_chunk(chunk_ptr block);
static chunk_ptr last_chunk(void);

static chunk_ptr extend_heap(size_t size);
static chunk_ptr find_fit(size_t size);
static void free_list_insert(chunk_ptr block);
static void free_list_remove(chunk_ptr block);
static chunk_ptr coalesce(chunk_ptr block);
static void split(chunk_ptr block, size_t size);

static void *heap_start = NULL;
static void *heap_end = NULL;

static chunk_ptr free_list = NULL;


/**
 * Utils
 */

static size_t make_header(size_t size, int status, int prev_inuse) {
    size_t header = (size & SIZE_MASK) | (status & 1);
#if HAS_PREV_INUSE
    if (prev_inuse) {
        header |= PREV_INUSE;
    }
#else
    (void) prev_inuse;
#endif
    return header;
}

static size_t get_size(chunk_ptr block) {
    return block->size & SIZE_MASK;
}

static size_t get_prev_size(chunk_ptr block) {
    btag_t *prev_footer = (btag_t *) ((char *) block - BTAG_SIZE);
    return prev_footer->size;
}

static void set_btag(chunk_ptr block, size_t size) {
    btag_t *footer = (btag_t *) ((char *) block + size - BTAG_SIZE);
    footer->size = size & SIZE_MASK;
}

static int get_status(chunk_ptr block) {
    return block->size & 1;
}

static void set_status(chunk_ptr block, int status) {
    block->size = (block->size & ~(size_t)1) | (status & 1);
}

static int get_prev_inuse(chunk_ptr block) {
#if HAS_PREV_INUSE
    return (block->size & PREV_INUSE) != 0;
#else
    (void) block;
    return 0;
#endif
}

static void set_prev_inuse(chunk_ptr block, int value) {
#if HAS_PREV_INUSE
    block->size = (block->size & ~(size_t)PREV_INUSE) |
                  (value ? PREV_INUSE : 0);
#else
    (void) block;
    (void) value;
#endif
}

static chunk_ptr next_chunk(chunk_ptr block) {
    size_t size = get_size(block);
    if ((void *) block >= heap_end - size) {
        return NULL;
    }
    return (chunk_ptr) ((char *) block + size);
}

/*
 * Validacao do boundary tag.
 *
 * Em PREV_INUSE=1 este caminho nem e chamado: o footer nao existe. Quando e
 * chamado, os testes abaixo sao necessarios mas nao suficientes sozinhos,
 * porque header e footer podem estar os dois em dados do usuario. O estado
 * confiavel e o bit PREV_INUSE; a validacao e a segunda barreira.
 */
static chunk_ptr prev_chunk(chunk_ptr block) {
    /*
     * O primeiro chunk do heap nao tem chunk anterior. A checagem tambem
     * evita ler block-8 antes de heap_start quando o allocator e usado sem
     * um chunk de guarda.
     */
    if ((void *) block <= heap_start) {
        BTAG_LOG("btag ignorado: bloco no inicio do heap\n");
        return NULL;
    }

    size_t prev_size = get_prev_size(block);
    uintptr_t block_addr = (uintptr_t) block;
    uintptr_t heap_addr = (uintptr_t) heap_start;
    uintptr_t cand_addr = 0;
    const char *motivo = NULL;
    chunk_ptr prev = NULL;

    if (prev_size <= block_addr - heap_addr) {
        cand_addr = block_addr - prev_size;
    }

    if (prev_size == 0) {
        motivo = "tamanho zero";
    } else if (prev_size % ALIGNMENT != 0) {
        motivo = "desalinhado";
    } else if (prev_size < MIN_BLOCK_SIZE) {
        motivo = "menor que o minimo";
    } else if (prev_size > block_addr - heap_addr) {
        motivo = "fora do heap";
    } else {
        prev = (chunk_ptr) cand_addr;

        if (get_size(prev) != prev_size) {
            motivo = "header nao bate com o footer";
        } else if (get_status(prev) != FREE) {
            motivo = "candidato nao esta livre";
        } else if (*(size_t *) ((char *) prev + prev_size - BTAG_SIZE) != prev_size) {
            /* Tautologico: esta posicao e a mesma de block-8. Fica explicito
             * no experimento justamente para mostrar que auto-consistencia
             * nao prova integridade. */
            motivo = "footer nao bate";
        }
    }

    if (motivo != NULL) {
        BTAG_LOG("btag rejeitado: prev_size=%zu candidato=%#lx motivo=%s\n",
                 prev_size, (unsigned long) cand_addr, motivo);
        return NULL;
    }

    BTAG_LOG("btag aceito: prev_size=%zu candidato=%p\n",
             prev_size, (void *) prev);
    return prev;
}


/**
 * Core helpers
 */

static chunk_ptr last_chunk(void) {
    if (heap_start == NULL || heap_start == heap_end) {
        return NULL;
    }

    chunk_ptr block = (chunk_ptr) heap_start;
    for (size_t i = 0; i < 1000000; i++) {
        chunk_ptr next = next_chunk(block);
        if (next == NULL || (char *) next <= (char *) block) {
            return block;
        }
        block = next;
    }
    return block;
}

static chunk_ptr extend_heap(size_t size) {
    chunk_ptr block = (chunk_ptr) sbrk(size);
    if (block == (void *) -1) {
        return NULL;
    }

    /*
     * Se o ultimo chunk do heap esta livre, o novo chunk nasce encostado
     * nele; nesse caso o footer anterior existe e PREV_INUSE=0. Caso
     * contrario, o anterior esta em uso e o footer nao pode ser lido.
     */
    int prev_inuse = 1;
    chunk_ptr last = last_chunk();
    if (last != NULL && get_status(last) == FREE) {
        prev_inuse = 0;
    }

    block->size = make_header(size, INUSE, prev_inuse);
    heap_end = (void *) block + size;
    return block;
}

static chunk_ptr find_fit(size_t size) {
    chunk_ptr block = free_list;
    while (block != NULL) {
        if (get_size(block) >= size) {
            free_list_remove(block);
            set_status(block, INUSE);
            return block;
        }
        block = block->next;
    }
    return NULL;
}

static void free_list_insert(chunk_ptr block) {
    block->next = free_list;
    block->prev = NULL;
    if (free_list != NULL) {
        free_list->prev = block;
    }
    free_list = block;
}

static void free_list_remove(chunk_ptr block) {
    if (block->prev != NULL) {
        block->prev->next = block->next;
    } else {
        free_list = block->next;
    }

    if (block->next != NULL) {
        block->next->prev = block->prev;
    }
}

static chunk_ptr coalesce(chunk_ptr block) {
    chunk_ptr prev_block = NULL;
    chunk_ptr next_block = next_chunk(block);
    size_t size = get_size(block);

    if (get_prev_inuse(block)) {
        BTAG_LOG("PREV_INUSE=1: btag em %p nao sera lido (chunk anterior em uso)\n",
                 (void *) ((char *) block - BTAG_SIZE));
    } else {
        prev_block = prev_chunk(block);
    }

    int prev_status = prev_block == NULL ? -1 : get_status(prev_block);
    int next_status = next_block == NULL ? -1 : get_status(next_block);

    if (prev_status == FREE && next_status == FREE) {
        int prev_prev_inuse = get_prev_inuse(prev_block);

        free_list_remove(next_block);
        free_list_remove(prev_block);

        size += get_size(prev_block) + get_size(next_block);
        prev_block->size = make_header(size, FREE, prev_prev_inuse);
        set_btag(prev_block, size);

        chunk_ptr after = next_chunk(prev_block);
        if (after != NULL) {
            set_prev_inuse(after, 0);
        }

        return prev_block;
    }
    if (prev_status == FREE) {
        int prev_prev_inuse = get_prev_inuse(prev_block);

        free_list_remove(prev_block);

        size += get_size(prev_block);
        prev_block->size = make_header(size, FREE, prev_prev_inuse);
        set_btag(prev_block, size);

        chunk_ptr after = next_chunk(prev_block);
        if (after != NULL) {
            set_prev_inuse(after, 0);
        }

        return prev_block;
    }
    if (next_status == FREE) {
        int block_prev_inuse = get_prev_inuse(block);

        free_list_remove(next_block);

        size += get_size(next_block);
        block->size = make_header(size, FREE, block_prev_inuse);
        set_btag(block, size);

        chunk_ptr after = next_chunk(block);
        if (after != NULL) {
            set_prev_inuse(after, 0);
        }

        return block;
    }

    return block;
}

static void split(chunk_ptr block, size_t size) {
    int block_prev_inuse = get_prev_inuse(block);
    size_t old_size = get_size(block);
    size_t new_size = old_size - size;

    chunk_ptr new_block = (chunk_ptr) ((char *) block + size);
    new_block->size = make_header(new_size, FREE, 1);
    set_btag(new_block, new_size);

    block->size = make_header(size, INUSE, block_prev_inuse);

    /*
     * O resto e livre; o chunk depois dele passa a ter um vizinho anterior
     * livre. O chunk alocado antes do resto esta em uso, entao o resto tem
     * PREV_INUSE=1 e nao le o tag que cai no fim dos dados do usuario.
     */
    chunk_ptr after = next_chunk(new_block);
    if (after != NULL) {
        set_prev_inuse(after, 0);
    }

    new_block = coalesce(new_block);
    free_list_insert(new_block);
}


void *pwnymalloc(size_t size) {
    if (heap_start == NULL) {
        heap_start = sbrk(0);
        heap_end = heap_start;
    }

    if (size == 0) {
        return NULL;
    }

    size_t total_size = MAX(ALIGN(size + INUSE_META_SIZE), MIN_BLOCK_SIZE);

    chunk_ptr block = find_fit(total_size);

    if (block == NULL) {
        block = extend_heap(total_size);
        if (block == NULL) {
            return NULL;
        }
    } else if (get_size((chunk_ptr) block) >= total_size + MIN_BLOCK_SIZE) {
        split(block, total_size);
    } else {
        /*
         * O bloco inteiro foi entregue. O chunk seguinte deixa de ter um
         * vizinho anterior livre.
         */
        chunk_ptr next = next_chunk(block);
        if (next != NULL) {
            set_prev_inuse(next, 1);
        }
    }

    return (void *) ((char *) block + INUSE_META_SIZE);
}


void pwnyfree(void *ptr) {
    if (ptr == NULL) {
        return;
    }

    chunk_ptr block = (chunk_ptr) ((char *) ptr - INUSE_META_SIZE);

    // check alignment and status
    if ((size_t) block % ALIGNMENT != 0 || get_status(block) != INUSE) {
        return;
    }

    set_status(block, FREE);
    set_btag(block, get_size(block));

    /*
     * O bloco agora esta livre: o chunk seguinte, se existir, passa a ter
     * um vizinho anterior livre. Isso e o que permite a coalescencia
     * legitima com o proximo e impede que o proximo leia um tag invalido.
     */
    chunk_ptr next = next_chunk(block);
    if (next != NULL) {
        set_prev_inuse(next, 0);
    }

    block = coalesce(block);

    printf("Block size: %zu\n", get_size(block));

    free_list_insert(block);
}
