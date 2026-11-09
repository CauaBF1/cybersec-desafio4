# Executar o pwnymalloc

## 1. Conferir os pré-requisitos

São necessários Docker em execução, Python 3 e Bash. Para o teste de menu abaixo, é necessário `nc` com suporte a `-N` e `-w`.

```bash
sudo docker info
python3 --version
bash --version
nc -h
```

**Verifique:** o Docker deve apresentar informações do servidor sem erro de conexão ou permissão; Python e Bash devem mostrar suas versões; o `nc` deve mostrar sua ajuda.

Confira os arquivos necessários:

```bash
ls subir.sh pwnymalloc/challenge/Dockerfile pwnymalloc/healthcheck/Dockerfile
bash -n subir.sh
```

**Verifique:** os três arquivos devem existir. `bash -n` deve terminar sem apresentar erros.

## 2. Construir e iniciar o serviço

```bash
sudo bash ./subir.sh
```

**Verifique:** o build deve terminar sem erro, e o script deve apresentar:

```text
OK: serviço disponível em 127.0.0.1:1337
```

Se o script informar que `pwnymalloc-lab` já existe, confira seu estado:

```bash
sudo docker ps -a --filter name=pwnymalloc-lab
```

Para continuar usando o container existente:

```bash
sudo docker start pwnymalloc-lab
```

Para construir e iniciar novamente do zero, remova somente o container deste laboratório e execute o script outra vez:

```bash
sudo docker rm -f pwnymalloc-lab
sudo bash ./subir.sh
```

**Verifique:** a remoção encerra o container e descarta seu estado interno. Os arquivos da pasta do projeto permanecem.

## 3. Conferir o container e testar o menu

```bash
sudo docker ps --filter name=pwnymalloc-lab
```

**Verifique:** o container deve estar com status `Up` e a porta deve aparecer como:

```text
127.0.0.1:1337->1337/tcp
```

Teste a opção 2 e depois a opção 5, que encerra a sessão:

```bash
printf '2\n5\n' | nc -N -w 5 127.0.0.1 1337
```

**Verifique:** devem aparecer o menu e esta resposta:

```text
Oh no! Our complaint database is currently down. Please try again later.
```

O menu aparece novamente e a conexão deve encerrar. Essa mensagem é uma resposta normal da opção 2.

Para acessar o menu interativamente:

```bash
nc 127.0.0.1 1337
```

Digite `2` e pressione Enter para testar a resposta. Digite `5` e pressione Enter para sair. Use TCP simples, sem `--ssl`.

**Limitação conhecida:** escolher a opção 1 como primeira operação e enviar uma reclamação apresentou `SIGSEGV` no programa oficial. Não use essa operação como critério de sucesso do ambiente. O teste de menu não verifica todas as funcionalidades.

## 4. Construir e executar o healthcheck oficial

O healthcheck contém a lógica de resolução fornecida pelos autores. Execute esta etapa quando puder realizar essa validação sem prejudicar a tentativa independente do grupo.

Construa a imagem:

```bash
sudo docker build --progress=plain \
  -t pwnymalloc-healthcheck:oficial \
  ./pwnymalloc/healthcheck
```

**Verifique:** o build deve terminar sem erro e criar a imagem `pwnymalloc-healthcheck:oficial`.

Com `pwnymalloc-lab` em execução, execute o teste e capture o resultado imediatamente:

```bash
sudo docker run --rm \
  --network container:pwnymalloc-lab \
  --workdir /home/user \
  --entrypoint /bin/bash \
  pwnymalloc-healthcheck:oficial \
  -lc 'export TERM=linux TERMINFO=/etc/terminfo; timeout 30s kctf_drop_privs /home/user/healthcheck.py'
resultado=$?
echo "Código de saída: $resultado"
```

**Verifique:** o resultado esperado é `Código de saída: 0`. O código `124` indica que o limite de tempo foi atingido. Outros códigos indicam falha e exigem conferir a mensagem apresentada.

O aviso sobre `distutils.sysconfig` apareceu na reprodução realizada, mas não impediu o teste de terminar com código 0. O healthcheck passar não significa que todas as operações do menu funcionam.

## 5. Consultar erros

Se o script não confirmar a disponibilidade, o serviço não responder ou o healthcheck falhar:

```bash
sudo docker ps -a --filter name=pwnymalloc-lab
sudo docker logs --tail 100 pwnymalloc-lab
```

**Verifique:** se o container encerrou, se há erro de inicialização ou se o processo da sessão caiu. `SIGSEGV` e status `139` indicam falha de acesso à memória no programa. `Broken pipe`, isoladamente, pode ocorrer quando uma conexão é fechada.

Se a porta estiver ocupada:

```bash
sudo docker ps
ss -ltnp 'sport = :1337'
```

Identifique quem usa a porta antes de encerrar qualquer processo ou container.

## 6. Encerrar ou retomar

Para parar o ambiente sem remover o container:

```bash
sudo docker stop pwnymalloc-lab
```

**Verifique:** ele não deve aparecer entre os containers em execução:

```bash
sudo docker ps --filter name=pwnymalloc-lab
```

Para retomar:

```bash
sudo docker start pwnymalloc-lab
```

Repita o teste de menu da seção 3 para verificar a resposta.

Para encerrar e remover somente o container do laboratório:

```bash
sudo docker rm -f pwnymalloc-lab
```

**Verifique:** não deve haver nenhuma entrada para ele:

```bash
sudo docker ps -a --filter name=pwnymalloc-lab
```
