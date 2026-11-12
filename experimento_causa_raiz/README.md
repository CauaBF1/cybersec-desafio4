# Experimento de causa raiz do pwnymalloc

Este diretório contém a contribuição experimental que testa a causa raiz por
intervenção no allocator. O relatório completo está em
[`EXPLICACAO.md`](EXPLICACAO.md).

## Rodar

```bash
bash run_experimento.sh
```

O script compila três variantes (`vuln`, `naive`, `hardened`), roda o mesmo
payload do exploit contra as três, executa a regressão funcional, faz smoke
tests do serviço endurecido e grava as evidências em `../evidencias/`.

## Arquivos

- `alloc_hardened.c` — allocator derivado; modo `naive` via
  `-DPWN_BTAG_CHECK_ONLY`, modo final com `PREV_INUSE`.
- `poc_causa_raiz.c` — ataque no nível do allocator, sem menu.
- `harness_exploit.py` — matriz de ataque no serviço local, só stdlib.
- `test_regressao.c` — testes funcionais e o teste da cauda envenenada no
  `split()`.
- `patches/` — diff completo e explicação dos dois modos.
- `Makefile` — builds e geração do diff.

O `pwnymalloc/challenge/alloc.c` original, o binário `chal` e o `flag.txt` não
são alterados.
