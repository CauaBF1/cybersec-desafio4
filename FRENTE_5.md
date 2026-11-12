# Frente 5 — causa raiz e mitigação do `pwnymalloc`

Esta frente parte da vulnerabilidade documentada pela Frente 2 e testa a causa
raiz por intervenção no allocator. O experimento executa o mesmo payload do
exploit contra três versões do `pwnymalloc` e mede o efeito de cada defesa.

O relatório completo, com a discussão passo a passo, está em
[`experimento_causa_raiz/EXPLICACAO.md`](experimento_causa_raiz/EXPLICACAO.md).

## Resultado principal

Checar apenas a consistência do boundary tag **não** resolve o problema: o
atacante controla tanto o header falso quanto o footer forjado, então a
checagem só prova que ele foi consistente consigo mesmo.

O que interrompe o exploit é um estado que o atacante não controla: o bit
`PREV_INUSE` no header do chunk. Com ele, `coalesce()` sabe quando o chunk
anterior está em uso e **nem lê** os 8 bytes que, nesse caso, são dados do
usuário. A mesma correção cobre o caminho do `split()`, onde o tag lido também
cai no fim dos dados de um chunk recém-alocado.

| Build | Payload | Block size | Overlap | Status | Flag |
|---|---|---:|---|---|---|
| `vuln` | original | 160 (`0xa0`) | sim | aprovado | sim |
| `vuln` | adaptado | 256 (`0x100`) | sim | aprovado | sim |
| `naive` | original | 80 (`0x50`) | não | negado | não |
| `naive` | adaptado | 256 (`0x100`) | sim | aprovado | sim |
| `hardened` | original | 80 (`0x50`) | não | negado | não |
| `hardened` | adaptado | 80 (`0x50`) | não | negado | não |

- `vuln`: allocator original do desafio, sem checagem.
- `naive`: só a validação de consistência do boundary tag — bloqueia o payload
  original, mas é contornada pelo payload adaptado.
- `hardened`: `PREV_INUSE` + validação do boundary tag — bloqueia os dois
  payloads e mantém o serviço funcionando.

## Entregáveis

- [`experimento_causa_raiz/alloc_hardened.c`](experimento_causa_raiz/alloc_hardened.c)
  — allocator derivado com as duas variantes (`-DPWN_BTAG_CHECK_ONLY` e
  `PREV_INUSE`). O `extend_heap()` acompanha o status do último chunk em
  `O(1)`, sem varrer o heap.
- [`experimento_causa_raiz/poc_causa_raiz.c`](experimento_causa_raiz/poc_causa_raiz.c)
  — ataque no nível do allocator, com os payloads original e adaptado.
- [`experimento_causa_raiz/harness_exploit.py`](experimento_causa_raiz/harness_exploit.py)
  — matriz de ataque no serviço local completo, só com a biblioteca padrão.
- [`experimento_causa_raiz/test_regressao.c`](experimento_causa_raiz/test_regressao.c)
  — regressão funcional: básico, reuso via free list, coalescência legítima,
  `split()`, estresse curto, `double_free`, ponteiro inválido e o teste da
  cauda envenenada.
- [`experimento_causa_raiz/patches/`](experimento_causa_raiz/patches/)
  — diff completo do allocator e explicação dos dois modos.
- [`evidencias/experimento-*`](evidencias/) — logs brutos de cada caso.

O `pwnymalloc/challenge/alloc.c`, o binário `chal` e o `flag.txt` originais não
foram alterados. O script confere isso antes de encerrar.

## Reprodução

```bash
cd experimento_causa_raiz
bash run_experimento.sh
```

O script compila as três variantes, roda a matriz nos dois níveis (serviço e
allocator puro), executa a regressão, faz smoke tests do serviço endurecido e
grava a saída consolidada em `../evidencias/experimento-causa-raiz.txt`.

Para inspecionar o diff da mitigação:

```bash
cd experimento_causa_raiz
make patches
less patches/alloc_hardened.diff
```

## Limitações

- O allocator é didático. A correção não inclui canários, safe-linking, cópia
  sombra de metadados ou verificação criptográfica do header. O modelo de
  ameaça é o do desafio: o atacante controla dados de chunks, não headers.
- Se o atacante puder corromper o header do chunk seguinte e limpar o
  `PREV_INUSE`, a proteção pode ser contornada. Uma versão de produção deveria
  proteger também a integridade dos headers.
- A variante `naive` é um controle didático, não a correção final.
- O harness usa o binário reconstruído localmente, não o container/nsjail.

## Referências

- [`RELATORIO_PWNYMALLOC.md`](RELATORIO_PWNYMALLOC.md) — relatório da
  vulnerabilidade e recomendações.
- [`exploit/frente_2/FRENTE_2.md`](exploit/frente_2/FRENTE_2.md) — PoC mínimo
  da Frente 2.
- [`pwnymalloc/SOLVE.md`](pwnymalloc/SOLVE.md) — write-up oficial dos autores.
- [`GUIA_REPRODUCAO.md`](GUIA_REPRODUCAO.md) — reprodução do ambiente.
- glibc MallocInternals: <https://sourceware.org/glibc/wiki/MallocInternals>
