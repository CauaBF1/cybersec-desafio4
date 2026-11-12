# Mudanças da Parte 2 (Eduardo) — Frente 4

Resumo do que foi acrescentado para fechar a minha metade do exploit (Pessoa B /
Eduardo): da primitiva de sobreposição até a flag, mais a automação e o harness de
confiabilidade. A metade da Pessoa A (Rafaela) já estava pronta e **não foi
alterada** — a Parte 2 a reaproveita por `import`.

## Arquivos novos

| Arquivo | O que é |
|---|---|
| `exploit/parte_2/solve_eduardo.py` | Segunda metade do solver + harness de confiabilidade. |
| `exploit/parte_2/PARTE_2.md` | Explicação da Parte 2 (plano, offsets, como rodar). |
| `MUDANCAS_PARTE_2.md` | Este arquivo. |

## Arquivos NÃO alterados (continuam da Pessoa A / dos autores)

- `exploit/parte_1/*` — solver da sobreposição (Rafaela). Reaproveitado por import.
- `pwnymalloc/*` — fonte do desafio, binário, solve oficial, healthcheck.
- Todo o resto do repositório (evidências, relatórios, frentes 2 e 5, etc.).

## Onde cada peça da Parte 2 mora, dentro de `solve_eduardo.py`

- `refund_status(io, req_id)` — a primitiva que faltava: opção 4 do menu, que
  dispara `print_flag()` quando o status está aprovado.
- `overwrite_status(io)` — realoca sobre o chunk sobreposto (novo refund request)
  e grava `p32(REFUND_APPROVED)` em `reason + CUT_STATUS_IN_REASON3 (0x10)`,
  corrompendo o `status` do pedido id 1.
- `read_flag(io)` — captura a flag `uiuctf{...}` da saída da opção 4.
- `exploit(io)` — cadeia completa: `A.build_overlap()` (Parte 1) → `overwrite_status()`
  → `refund_status()` → `read_flag()`.
- `loop(n)` — **harness de confiabilidade**: roda o exploit inteiro em `n`
  processos locais e reporta a taxa de sucesso (esperado 100%, allocator
  determinístico).

## Como a Parte 2 se liga à Parte 1

O `solve_eduardo.py` faz `import solve_rafaela as A` e `import heap_layout as L`
(da pasta `../parte_1`). Então:

- os offsets (`CUT_STATUS_IN_REASON3`, `OVERLAP_SIZE`, etc.) continuam saindo do
  único `heap_layout.py` — nada é recalculado nem copiado;
- a sobreposição é criada por `A.build_overlap()` — a Parte 2 não reimplementa a
  Parte 1, só continua de onde ela para.

## Como verificar (ambiente Linux de reprodução do desafio)

```bash
cd exploit/parte_2
python3 solve_eduardo.py          # -> [+] FLAG: uiuctf{...}
python3 solve_eduardo.py LOOP=100 # -> [+] confiabilidade: 100/100 = 100.0%
```

Detalhe: o `./chal` é ELF Linux e o exploit usa `pwntools`, então roda no ambiente
Linux de reprodução (ver `GUIA_REPRODUCAO.md`), não no Windows onde o código foi
escrito. O caminho vencedor da Parte 2 é o mesmo do solve oficial
(`pwnymalloc/solve.py`): escrever `p32(1)` em `reason+0x10` e consultar o id 1.
