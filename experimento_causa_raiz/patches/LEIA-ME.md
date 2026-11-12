# Patches do allocator

`alloc_hardened.diff` é o diff completo entre o allocator original do desafio
(`pwnymalloc/challenge/alloc.c`) e a versão de `experimento_causa_raiz/`.

O mesmo arquivo implementa as duas etapas do experimento:

- **Sem macro** — variante final: `PREV_INUSE` (bit 1) + validação do boundary
  tag. É a que bloqueia o payload original e o adaptado.
- **Com `-DPWN_BTAG_CHECK_ONLY`** — variante didática: só a validação do
  boundary tag. Ela bloqueia o payload original, mas é contornável porque
  header e footer falsos estão ambos em memória controlada pelo atacante.

Os builds são feitos pelo `Makefile` da pasta:

```bash
make build/chal_naive     # -DPWN_BTAG_CHECK_ONLY -DPWN_DEBUG
make build/chal_hardened  # -DPWN_DEBUG
```

O relatório `../EXPLICACAO.md` explica os dois caminhos e mostra os números do
bypass.
