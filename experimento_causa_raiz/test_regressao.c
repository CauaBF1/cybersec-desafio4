/*
 * test_regressao.c -- testes funcionais do allocator endurecido.
 *
 * Cada teste roda em um processo separado (o runner chama o binario uma vez
 * por nome) porque o allocator tem estado global e o heap nao e reiniciado.
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>

#include "alloc.h"

/*
 * O allocator original le o tag em block-8 sem checar o limite inferior. Se o
 * primeiro chunk do heap for liberado, essa leitura cai antes de heap_start e
 * pode falhar (um caminho compativel com o SIGSEGV conhecido da opcao 1 do
 * menu como primeira operacao). Em todos os testes alocamos uma guarda que
 * nunca e liberada, para que os chunks testados tenham um vizinho anterior
 * real.
 */
static void alocar_guarda(void) {
    void *guarda = pwnymalloc(0x20);
    assert(guarda != NULL);
    (void) guarda;
}

static void test_basico(void) {
    alocar_guarda();

    void *a = pwnymalloc(0x20);
    void *b = pwnymalloc(0x40);

    assert(a != NULL);
    assert(b != NULL);
    assert((char *) b > (char *) a);

    pwnyfree(b);
    pwnyfree(a);

    puts("[OK] basico");
}

/*
 * Coalescencia legitima com o chunk anterior livre:
 *   A (0x30) e liberado no topo;
 *   B (0x50) e maior que A, entao o heap e estendido depois de A;
 *   liberar B deve fundir A+B em 0x80;
 *   uma alocacao de 0x60 (total 0x70) deve caber no bloco fundido e
 *   devolver exatamente o ponteiro de A.
 */
static void test_prev_livre(void) {
    alocar_guarda();

    void *a = pwnymalloc(0x20);
    assert(a != NULL);

    pwnyfree(a);

    void *b = pwnymalloc(0x40);
    assert(b != NULL);
    assert((char *) b == (char *) a + 0x30);

    pwnyfree(b);

    void *c = pwnymalloc(0x60);
    assert(c != NULL);
    assert(c == a);

    pwnyfree(c);

    puts("[OK] prev_livre");
}

/*
 * Split: libera 0x110, aloca 0x50 do inicio e depois 0xb0 do resto.
 */
static void test_split(void) {
    alocar_guarda();

    void *a = pwnymalloc(0x100);
    assert(a != NULL);

    pwnyfree(a);

    void *b = pwnymalloc(0x40);
    assert(b != NULL);
    assert(b == a);

    void *c = pwnymalloc(0xa0);
    assert(c != NULL);
    assert(c == (char *) a + 0x50);

    pwnyfree(c);
    pwnyfree(b);

    puts("[OK] split");
}

/*
 * Reuso direto via free list: liberar e pedir o mesmo tamanho deve devolver
 * exatamente o mesmo bloco, sem estender o heap e sem perder a integridade.
 */
static void test_reuso(void) {
    alocar_guarda();

    void *a = pwnymalloc(0x20);
    assert(a != NULL);

    pwnyfree(a);

    void *b = pwnymalloc(0x20);
    assert(b != NULL);
    assert(b == a);

    pwnyfree(b);

    puts("[OK] reuso");
}

/*
 * Estresse curto: varias alocacoes pequenas, liberacao de todas e uma
 * alocacao final. Prova que o bookkeeping de PREV_INUSE continua consistente
 * depois de varios extend_heap()/free().
 */
static void test_estresse(void) {
    alocar_guarda();

    void *ptrs[64];
    for (int i = 0; i < 64; i++) {
        ptrs[i] = pwnymalloc(0x18);
        assert(ptrs[i] != NULL);
    }

    for (int i = 0; i < 64; i++) {
        pwnyfree(ptrs[i]);
    }

    void *final = pwnymalloc(0x10);
    assert(final != NULL);
    pwnyfree(final);

    puts("[OK] estresse");
}

/*
 * O mesmo bug aparece no split(): o coalesce() do resto le um tag que cai no
 * fim dos dados do chunk recem-alocado. Aqui plantamos um tag e um header
 * falsos nessa regiao antes de liberar o bloco grande. Com PREV_INUSE=1 o
 * split nao le o tag e o resto continua em x+0x50; sem o bit, o resto salta
 * para dentro dos dados de B (x+0x20) e cria sobreposicao.
 *
 * O runner espera sucesso no build hardened e falha de proposito nos builds
 * vuln e naive, que sao o controle positivo da vulnerabilidade.
 */
static void test_cauda_envenenada(void) {
    alocar_guarda();

    void *x = pwnymalloc(0x100);
    assert(x != NULL);

    memset(x, 0, 0x100);

    /*
     * chunk de x = x-8. O split de 0x50 coloca o resto em chunk+0x50 e le o
     * tag em chunk+0x48 = x+0x40. Plantamos:
     *   header falso em chunk+0x20 = x+0x18, size 0x30 (par = FREE);
     *   tag 0x30 em x+0x40.
     * O header fica depois dos 24 bytes de metadados da free list, para nao
     * ser sobrescrito quando x e liberado.
     */
    uint64_t fake_size = 0x30;
    uint64_t tag = 0x30;
    memcpy((char *) x + 0x18, &fake_size, sizeof(fake_size));
    memcpy((char *) x + 0x40, &tag, sizeof(tag));

    fprintf(stderr, "[teste] x=%p fake_hdr=%p tag_pos=%p\n",
            x, (void *) ((char *) x + 0x18), (void *) ((char *) x + 0x40));

    pwnyfree(x);

    void *b = pwnymalloc(0x40);
    assert(b != NULL);
    assert(b == x);

    void *c = pwnymalloc(0xb0);
    assert(c != NULL);
    assert(c == (char *) x + 0x50);

    puts("[OK] cauda_envenenada");
}

static void test_double_free(void) {
    alocar_guarda();

    void *a = pwnymalloc(0x20);
    assert(a != NULL);

    pwnyfree(a);
    pwnyfree(a);

    puts("[OK] double_free");
}

static void test_ponteiro_invalido(void) {
    alocar_guarda();

    void *a = pwnymalloc(0x20);
    assert(a != NULL);

    pwnyfree(NULL);
    pwnyfree((char *) a + 1);

    puts("[OK] ponteiro_invalido");
}

int main(int argc, char **argv) {
    /*
     * Mesmo motivo do PoC: o allocator usa sbrk() e o primeiro printf nao
     * pode alocar buffer de stdio via malloc no meio do heap customizado.
     */
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    if (argc != 2) {
        fprintf(stderr,
                "uso: %s {basico|prev_livre|split|reuso|estresse|"
                "cauda_envenenada|double_free|ponteiro_invalido}\n",
                argv[0]);
        return 2;
    }

    if (strcmp(argv[1], "basico") == 0) {
        test_basico();
    } else if (strcmp(argv[1], "prev_livre") == 0) {
        test_prev_livre();
    } else if (strcmp(argv[1], "split") == 0) {
        test_split();
    } else if (strcmp(argv[1], "reuso") == 0) {
        test_reuso();
    } else if (strcmp(argv[1], "estresse") == 0) {
        test_estresse();
    } else if (strcmp(argv[1], "cauda_envenenada") == 0) {
        test_cauda_envenenada();
    } else if (strcmp(argv[1], "double_free") == 0) {
        test_double_free();
    } else if (strcmp(argv[1], "ponteiro_invalido") == 0) {
        test_ponteiro_invalido();
    } else {
        fprintf(stderr, "teste desconhecido: %s\n", argv[1]);
        return 2;
    }

    return 0;
}
