# Experimento de causa raiz: a checagem do boundary tag interrompe o exploit?

Este documento descreve um experimento controlado para provar a causa raiz da
vulnerabilidade do `pwnymalloc` por intervenção no allocator. O mesmo payload do
exploit é executado contra três versões do allocator. A única variável alterada
é a forma como o `coalesce()` decide se pode confiar no boundary tag.

O resultado principal: a versão com `PREV_INUSE` e validação do tag derruba o
exploit original **e** um payload adaptado que passa por uma checagem ingênua.
O processo continua funcionando e não crasha.

## Resumo

- A falha não é apenas “falta validar o tamanho no footer”. O footer lido em
  `block - 8` fica exatamente na região que, quando o chunk anterior está em
  uso, pertence aos dados do usuário. Validar o footer contra um header que o
  atacante também controla é auto-consistência, não integridade.
- A checagem ingênua (tamanho alinhado, dentro do heap, header igual ao footer,
  candidato livre) bloqueia o payload original, mas é contornável com um header
  falso de `0xb0` e um footer forjado de `0xb0`.
- O estado confiável que falta é o `PREV_INUSE`: um bit no header do chunk atual
  que diz se o chunk anterior está em uso. Com ele, o `coalesce()` nem lê o
  footer quando o anterior está em uso. O payload original e o adaptado falham.
- A correção também cobre o mesmo problema no `split()`, onde o tag lido cai no
  fim dos dados do chunk recém-alocado.
- Os testes de regressão mostram que a coalescência legítima com o chunk
  anterior livre continua funcionando.

## Pergunta e hipótese

**Pergunta:** o exploit depende de o allocator interpretar como metadado um
valor que está em memória controlada pelo atacante. Se adicionarmos uma
checagem de integridade do boundary tag, o exploit quebra?

**Hipótese:** uma checagem que só compara o footer com um header próximo é
insuficiente, porque os dois lados podem ser forjados. O exploit só quebra de
forma robusta quando o allocator tem um estado confiável sobre o chunk anterior
e só lê o footer quando esse estado autoriza a leitura.

## Como o allocator funciona

Cada chunk começa com um header de 8 bytes que guarda o tamanho e o status do
chunk atual no bit 0 (`1` = em uso, `0` = livre). Um chunk em uso tem só esse
header antes dos dados. Um chunk livre tem, além do header, os ponteiros
`next`/`prev` da free list e um footer de 8 bytes no fim, com o próprio tamanho.
Esse footer é o boundary tag.

Quando um bloco é liberado, `pwnyfree()` marca o chunk como livre, grava seu
footer e chama `coalesce()`. Para achar o chunk anterior, `coalesce()` lê o
footer em `block - 8` e usa o valor como distância para trás:

```c
static size_t get_prev_size(chunk_ptr block) {
    btag_t *prev_footer = (btag_t *) ((char *) block - BTAG_SIZE);
    return prev_footer->size;
}

static chunk_ptr prev_chunk(chunk_ptr block) {
    if ((void *) block - get_prev_size(block) < heap_start ||
        get_prev_size(block) == 0) {
        return NULL;
    }
    return (chunk_ptr) ((char *) block - get_prev_size(block));
}
```

O problema: o footer só existe de verdade quando o chunk anterior está livre.
Quando ele está em uso, os 8 bytes em `block - 8` são os últimos bytes dos dados
daquele chunk. O allocator original não tem nenhum bit equivalente ao
`PREV_INUSE` do glibc para saber que não pode ler ali.

## Desenho experimental

Três builds, todos com o mesmo `main.c` do desafio:

| Build | Allocator | O que tem |
|---|---|---|
| `vuln` | `pwnymalloc/challenge/alloc.c` original | nenhuma checagem |
| `naive` | `alloc_hardened.c -DPWN_BTAG_CHECK_ONLY` | só a checagem de consistência do tag |
| `hardened` | `alloc_hardened.c` | `PREV_INUSE` + checagem do tag |

Dois payloads, ambos com a mesma sequência de menu:

- **original**: header falso de `0x50` em `base+0x78`, `prev_size` forjado
  `0xa8`, status de RR1 escrito em `reason+0x10`.
- **adaptado**: header falso de `0xb0` em `base+0x70`, `prev_size` forjado
  `0xb0`, status de RR1 escrito em `reason+0x18`.

O payload adaptado existe para atacar a checagem ingênua. Ele escolhe valores
que satisfazem todas as comparações dela: `0xb0` é múltiplo de 16, é maior que o
tamanho mínimo, o candidato `base+0x70` está dentro do heap, o header falso
declara `0xb0`, o candidato está livre (bit 0 = 0) e o footer do chunk falso cai
exatamente em `base+0x118`, que é o mesmo lugar de onde o tag é lido.

A evidência é coletada em dois níveis:

1. **Serviço local completo**: `main.c` + allocator, com o `flag.txt` do
   repositório, verificando `Block size`, status aprovado/negado e a flag.
2. **Allocator puro**: `poc_causa_raiz.c`, que repete o ataque sem menu e
   verifica o overlap e o campo `status`.

Os dois níveis usam a mesma aritmética de offsets. O harness não usa pwntools:
é só `subprocess` e `struct`, para não depender de bibliotecas externas.

Como controle do rebuild, o binário `build/chal_vuln` (compilado a partir de
`main.c` + `alloc.c` originais) produz saída byte a byte idêntica ao `chal`
versionado no repositório para o payload original: `Block size: 160` e a mesma
flag. O harness confere essa igualdade automaticamente antes de rodar a matriz
(`experimento-referencia-chal.log`). Ou seja, a comparação não está medindo uma
diferença introduzida pelo processo de compilação.

## Etapa A: a checagem ingênua

A variante `naive` adiciona a `prev_chunk()` as validações:

- `prev_size != 0`;
- `prev_size % 16 == 0`;
- `prev_size >= MIN_BLOCK_SIZE` (`0x20`);
- candidato dentro do heap;
- `get_size(candidato) == prev_size` (header bate com o footer);
- candidato com status `FREE`;
- o footer do candidato também contém `prev_size`.

Com o payload original, a checagem rejeita:

```text
[pwnymalloc] btag rejeitado: prev_size=168 candidato=...078 motivo=desalinhado
Block size: 80
Your refund request has been denied.
```

O exploit original para: o complaint não funde com o chunk falso, não nasce o
chunk sobreposto e o status de RR1 continua `DENIED`. Até aqui, a resposta
literal à pergunta seria “sim, a checagem quebra o exploit”.

### Por que a checagem ingênua não basta

O payload adaptado faz a checagem passar:

```text
[pwnymalloc] btag aceito: prev_size=176 candidato=...070
Block size: 256
[pwnymalloc] btag rejeitado: prev_size=0 candidato=...100 motivo=tamanho zero
Your refund request has been approved!
uiuctf{the_memory_train_went_off_the_tracks}
```

`256 = 0x100 = 0x50` (complaint) `+ 0xb0` (chunk falso). O exploit voltou a
funcionar.

O motivo é estrutural. A checagem compara o footer com um header que o atacante
também escreveu. O footer está em `block - 8`, que é o fim do `reason` de RR1;
o header falso está no `reason` de RR0. Os dois são dados do usuário. A última
conferência (“o footer do candidato também contém o tamanho”) lê exatamente os
mesmos 8 bytes do tag, então é tautológica. A checagem garante que o atacante é
consistente consigo mesmo, não que o allocator escreveu aqueles metadados.

Em uma frase: **comparar apenas o boundary tag com o header vizinho não
distingue um footer forjado de um footer real quando os dois ficam na mesma
posição e o atacante controla os bytes.** É preciso um estado que o atacante não
controle, como o `PREV_INUSE`.

## Etapa B: o estado confiável `PREV_INUSE`

A variante `hardened` usa o bit 1 do header para registrar se o chunk anterior
está em uso:

```c
#define PREV_INUSE 2

static size_t get_size(chunk_ptr block) {
    return block->size & ~(size_t)(ALIGNMENT - 1);
}

/* no coalesce: */
if (get_prev_inuse(block)) {
    prev_block = NULL;          /* não existe footer para ler */
} else {
    prev_block = prev_chunk(block); /* footer legítimo: valida e usa */
}
```

O bit é mantido apenas por código do allocator:

- `extend_heap()` olha o último chunk do heap para decidir o `PREV_INUSE` do
  chunk novo;
- `split()` marca o resto como livre com `PREV_INUSE=1`, porque o chunk
  imediatamente anterior a ele é o chunk recém-alocado e está em uso;
- `pwnyfree()` limpa o `PREV_INUSE` do chunk seguinte, porque o bloco liberado
  agora é um vizinho anterior livre;
- ao entregar um chunk livre inteiro, o allocator marca `PREV_INUSE=1` no chunk
  seguinte.

Com o payload original, o header de C3 tem `PREV_INUSE=1` porque C2 (RR1) está
em uso. O `coalesce()` não chama `get_prev_size()`:

```text
[pwnymalloc] PREV_INUSE=1: btag em ...118 nao sera lido (chunk anterior em uso)
Block size: 80
Your refund request has been denied.
```

O payload adaptado também falha, e pelo mesmo motivo: os bytes forjados em
`base+0x118` nunca são interpretados como metadado. O valor `0xb0` continua
sendo apenas dado do `reason` de RR1.

A validação da Etapa A continua no código como segunda barreira, para o caso em
que o chunk anterior realmente está livre. Ela não é a prova de integridade; a
prova é o bit de estado.

## Matriz de resultados

Saída real consolidada dos dois níveis (serviço local para `Block size` e
flag; PoC no allocator para overlap e status):

| Build | Payload | Block size | Overlap | Status | Flag |
|---|---|---:|---|---|---|
| `vuln` | original | 160 (`0xa0`) | sim | aprovado | sim |
| `vuln` | adaptado | 256 (`0x100`) | sim | aprovado | sim |
| `naive` | original | 80 (`0x50`) | não | negado | não |
| `naive` | adaptado | 256 (`0x100`) | sim | aprovado | sim |
| `hardened` | original | 80 (`0x50`) | não | negado | não |
| `hardened` | adaptado | 80 (`0x50`) | não | negado | não |

O PoC no nível do allocator produziu exatamente a mesma matriz:

```text
build      payload     block  overlap  status   rc resultado
vuln       original      160      sim     sim    0 OK
vuln       adaptado      256      sim     sim    0 OK
naive      original       80      nao     nao    0 OK
naive      adaptado      256      sim     sim    0 OK
hardened   original       80      nao     nao    0 OK
hardened   adaptado       80      nao     nao    0 OK
```

Os logs brutos de cada caso estão em `evidencias/experimento-*.log`.

## O mesmo problema no `split()`

A falha não é exclusiva do `pwnyfree()` do complaint. Quando o `split()` separa
um chunk livre, ele cria um resto livre e chama `coalesce()` nesse resto. O
chunk imediatamente anterior ao resto é o chunk recém-alocado, e o tag lido cai
no fim dos dados desse chunk. O allocator original lê ali do mesmo jeito.

O teste `cauda_envenenada` planta um header falso e um tag falso nessa região
antes de liberar o bloco grande. O comportamento observado:

```text
# vuln: o coalesce aceita o chunk falso e o resto nasce dentro dos dados
Block size: 272
test_vuln: test_regressao.c:143: ... Assertion `c == (char *) x + 0x50' failed.

# naive: a checagem aceita o par auto-consistente e o problema continua
[pwnymalloc] btag aceito: prev_size=48 candidato=...050
test_naive: ... Assertion `c == (char *) x + 0x50' failed.

# hardened: o split marca PREV_INUSE=1 e nem lê o tag
[pwnymalloc] PREV_INUSE=1: btag em ...078 nao sera lido (chunk anterior em uso)
[OK] cauda_envenenada
```

Isso mostra que a correção não é um remendo só no caminho do menu; ela cobre o
segundo caminho em que o mesmo boundary tag ambíguo é lido.

## Regressão funcional

Os testes rodam em processos separados, porque o allocator tem estado global e
o heap não é reiniciado. Eles começam com uma alocação de guarda que nunca é
liberada: o allocator original lê `block - 8` sem checar o limite inferior, e
liberar o primeiro chunk do heap pode cair antes de `heap_start` (um caminho
compatível com o `SIGSEGV` conhecido quando a opção 1 é a primeira operação do
menu). Os testes também chamam `setvbuf(stdout, NULL, _IONBF, 0)`, pelo mesmo
motivo que o `main.c` do desafio: o primeiro `printf` não pode alocar buffer de
stdio via `malloc` no meio do heap customizado.

Resultados:

- `basico`: passa nos três builds.
- `prev_livre`: passa nos três. Libera A, aloca B maior (o heap estende depois
  de A) e libera B; o bloco fundido tem `0x80` e a alocação seguinte devolve
  exatamente o ponteiro de A. Isso prova que a validação do tag não quebrou a
  coalescência legítima com o chunk anterior livre.
- `split`: passa nos três.
- `reuso`: passa nos três. Liberar e pedir o mesmo tamanho devolve exatamente
  o mesmo bloco pela free list, sem estender o heap.
- `estresse`: passa nos três. Sessenta e quatro alocações pequenas, liberação
  de todas e uma alocação final mantêm o bookkeeping de `PREV_INUSE`
  consistente.
- `cauda_envenenada`: falha em `vuln` e `naive` (o ataque funciona) e passa em
  `hardened`.
- `double_free` e `ponteiro_invalido`: passam nos três; as checagens existentes
  continuam ignorando liberações inválidas.

Smoke tests do serviço endurecido:

- `2` seguido de `5` continua mostrando a mensagem normal de “complaint database
  is currently down”;
- um pedido de reembolso normal continua mostrando “denied”.

Ou seja, o allocator endurecido não impede o uso normal do serviço; ele só
recusa interpretar como metadado um valor que não foi escrito pelo allocator.

## Por que o processo não crasha

Nos casos `hardened/*`, o ataque não gera corrupção seguida de falha: o
`coalesce()` simplesmente não entra no caminho de leitura do footer. O complaint
é liberado sozinho, com `Block size: 80`, e a alocação seguinte estende o heap.
O programa continua, responde “denied” e sai com código 0 depois da opção 5.

Isso é deliberado: a correção falha de forma segura. Em um allocator de
produção, uma inconsistência de metadados poderia até abortar o processo; aqui
queremos mostrar que o exploit perde a primitiva sem derrubar o serviço.

## Limitações e ameaças à validade

- O allocator é didático. A correção não inclui canários, safe-linking, cópia
  sombra de metadados ou verificação criptográfica do header. O modelo de ameaça
  é o do desafio: o atacante controla dados de chunks, não os headers.
- Se o atacante puder corromper o header do chunk seguinte e limpar o
  `PREV_INUSE`, a proteção pode ser contornada. Uma versão de produção deveria
  proteger também a integridade dos headers.
- A variante `naive` é um controle didático, não a correção final. Ela mostra
  por que uma checagem auto-referencial não resolve o problema.
- O harness usa o binário local reconstruído a partir de `main.c` e do
  allocator, não o container/nsjail. O `healthcheck.py` oficial é, ele próprio,
  um exploit: contra o serviço endurecido ele deve falhar, e por isso não é
  usado como teste de regressão funcional.
- O `extend_heap()` mantém o status do último chunk em uma variável
  (`heap_tail_inuse`), então descobrir o `PREV_INUSE` do chunk novo é `O(1)`;
  não é preciso varrer o heap.
- O experimento depende de o layout dos chunks ser determinístico. O allocator
  usa `sbrk()` diretamente e o `main.c` desabilita o buffer de stdio; os testes
  fazem o mesmo. Sem isso, o primeiro `printf` pode deslocar o break e os chunks
  deixam de sair encostados.

## Como reproduzir

```bash
cd experimento_causa_raiz
bash run_experimento.sh
```

O script compila as três variantes, roda a matriz nos dois níveis, executa a
regressão, faz os smoke tests e confere que `alloc.c`, `chal` e `flag.txt`
originais não foram alterados. A saída consolidada fica em
`../evidencias/experimento-causa-raiz.txt`.

Comandos individuais:

```bash
make all
python3 harness_exploit.py
make patches

./build/poc_hardened original
./build/poc_hardened adaptado
./build/test_hardened prev_livre
./build/test_hardened cauda_envenenada
```

Para ver o diff completo do allocator:

```bash
less patches/alloc_hardened.diff
```

## Conclusão

A checagem ingênua do boundary tag é necessária, mas não é suficiente: ela
bloqueia o payload original e é contornada por um payload que torna header e
footer auto-consistentes. O que realmente interrompe o exploit é o estado
confiável `PREV_INUSE`, que diz ao `coalesce()` quando o footer não existe. Com
ele, nem o payload original nem o adaptado chegam a fazer o allocator
interpretar dados do usuário como metadado.

Em termos de causa raiz: o exploit não quebra porque “falta um `if`”. Ele quebra
quando o allocator deixa de tratar como confiável um valor que está na mesma
posição e no mesmo domínio de controle do atacante.

## Referências

- `pwnymalloc/challenge/alloc.c` — allocator original do desafio.
- `RELATORIO_PWNYMALLOC.md` — relatório da vulnerabilidade e recomendações.
- `exploit/frente_2/FRENTE_2.md` — PoC mínimo da Frente 2.
- `pwnymalloc/SOLVE.md` — write-up oficial dos autores.
- `GUIA_REPRODUCAO.md` — reprodução do ambiente e o `SIGSEGV` conhecido da
  opção 1 como primeira operação.
- glibc MallocInternals, em especial `PREV_INUSE` e boundary tags:
  <https://sourceware.org/glibc/wiki/MallocInternals>
