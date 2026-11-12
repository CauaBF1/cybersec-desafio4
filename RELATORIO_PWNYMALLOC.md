# Relatório técnico: validação incorreta de boundary tag no pwnymalloc

## Resumo

O allocator customizado `pwnymalloc` usa o tamanho gravado no boundary tag
imediatamente anterior a um bloco para localizar o chunk precedente durante a
coalescência. Esse footer só é definido quando o chunk precedente está livre.
Quando ele está em uso, o allocator ainda lê e usa os bytes nessa posição sem
confirmar que o footer é válido.

Como consequência, dados adjacentes ao bloco podem ser interpretados como
metadados de tamanho e influenciar o endereço do chunk que a coalescência
considera como anterior. Isso viola a integridade dos metadados do heap e pode
levar a operações posteriores sobre limites incorretos.

## Escopo afetado

- `pwnymalloc/challenge/alloc.c`
  - `get_prev_size`: lê o valor imediatamente anterior ao chunk.
  - `prev_chunk`: usa esse valor para calcular o endereço do chunk anterior.
  - `coalesce`: consulta e opera sobre o chunk retornado por `prev_chunk`.
  - `pwnyfree`: inicia a coalescência após marcar um chunk como livre.
- `pwnymalloc/challenge/main.c`
  - `handle_complaint`: caminho da aplicação que libera um buffer usando
    `pwnyfree`.

## Causa raiz

`get_prev_size` calcula `block - BTAG_SIZE` e lê `prev_footer->size`. O valor
retornado é então usado por `prev_chunk` para recuar na memória. A validação
existente verifica o limite inferior do heap e o caso de tamanho zero, mas não
verifica se o chunk anterior está livre.

O allocator mantém um bit de estado para o chunk atual, mas não mantém nem
consulta um indicador equivalente a `PREV_INUSE` antes de interpretar o
boundary tag anterior. Portanto, quando o chunk anterior está em uso, a posição
lida não é garantidamente um footer escrito pelo allocator.

**Causa raiz em uma frase:** a coalescência confia em um boundary tag que só é
válido quando o chunk anterior está livre, sem verificar essa condição antes
de ler e usar o valor.

## Demonstração de conceito

A falha pode ser confirmada por inspeção do fluxo, sem executar uma entrada que
corrompa o heap:

1. `pwnyfree` marca o chunk recebido como livre e chama `coalesce`.
2. `coalesce` consulta o chunk anterior por meio de `prev_chunk`.
3. `prev_chunk` obtém um tamanho por `get_prev_size` e usa esse valor para
   calcular o endereço anterior.
4. Nenhuma verificação anterior confirma que o chunk precedente está livre e
   que o valor lido foi gravado como um footer válido.

Essa sequência demonstra a leitura e o uso de metadados sem validação do estado
do chunk precedente. Não é necessário enviar dados especialmente construídos,
executar a cadeia de exploração ou alterar o serviço para verificar a causa
raiz no código.

## Impacto

A coalescência pode tratar dados que não são um footer válido como metadados do
heap. Isso pode fazer o allocator calcular um chunk anterior incorreto e
corromper o estado da lista livre ou de alocações adjacentes. No contexto do
desafio, isso compromete a integridade do heap e pode afetar dados mantidos por
outras alocações.

Este relatório registra a condição vulnerável no allocator do desafio. Não
documenta payloads, offsets de heap nem uma cadeia de exploração.

## Recomendações

- Só leia `prev_size` e localize o chunk anterior quando o estado do chunk
  precedente indicar que ele está livre.
- Armazene e mantenha explicitamente esse estado, ou use um desenho de
  metadados que permita validar a presença do footer antes de acessá-lo.
- Antes de coalescer, valide alinhamento, limites, tamanho mínimo e consistência
  dos metadados dos chunks envolvidos.
- Adicione testes para as quatro combinações de estado dos chunks anterior e
  seguinte, incluindo a condição em que o chunk anterior está em uso.

## Referências no código

- `pwnymalloc/challenge/alloc.c`: `get_prev_size`, `prev_chunk`, `coalesce` e
  `pwnyfree`.
- `pwnymalloc/challenge/main.c`: `handle_complaint`.
