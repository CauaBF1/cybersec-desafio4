#!/usr/bin/env bash
set -Eeuo pipefail

RAIZ="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DESAFIO="$RAIZ/pwnymalloc"
IMAGEM="pwnymalloc-local:oficial"
CONTAINER="pwnymalloc-lab"

command -v docker >/dev/null || {
  echo "Erro: Docker não está instalado." >&2
  exit 1
}

command -v python3 >/dev/null || {
  echo "Erro: Python 3 não está instalado." >&2
  exit 1
}

docker info >/dev/null 2>&1 || {
  echo "Erro: não foi possível acessar o Docker." >&2
  echo "Confira o daemon e as permissões do seu usuário." >&2
  exit 1
}

[[ -f "$DESAFIO/challenge/Dockerfile" ]] || {
  echo "Erro: pasta oficial do desafio não encontrada." >&2
  exit 1
}

# Evita reutilizar silenciosamente um container de uma imagem anterior.
if docker container inspect "$CONTAINER" >/dev/null 2>&1; then
  echo "Erro: já existe um container chamado $CONTAINER." >&2
  echo "Confira-o com: docker ps -a --filter name=$CONTAINER" >&2
  echo "Para iniciar uma reprodução nova, remova apenas esse container." >&2
  exit 1
fi

echo "Construindo a imagem..."
docker build -t "$IMAGEM" "$DESAFIO/challenge"

echo "Iniciando o serviço..."
docker run -d \
  --name "$CONTAINER" \
  --privileged \
  -p 127.0.0.1:1337:1337 \
  "$IMAGEM"

echo "Aguardando a resposta do serviço..."
if ! python3 - <<'PY'
import socket
import time

limite = time.monotonic() + 30

while time.monotonic() < limite:
    try:
        with socket.create_connection(("127.0.0.1", 1337), timeout=2) as conexao:
            conexao.settimeout(2)
            resposta = b""

            while b"customer service portal" not in resposta:
                parte = conexao.recv(4096)
                if not parte:
                    break
                resposta += parte
                if len(resposta) > 65536:
                    break

            if b"customer service portal" in resposta:
                print(resposta.decode(errors="replace"))
                print("OK: serviço disponível em 127.0.0.1:1337")
                raise SystemExit(0)

    except OSError:
        pass

    time.sleep(1)

raise SystemExit("Erro: o serviço não respondeu como esperado em 30 segundos.")
PY
then
  docker logs --tail 100 "$CONTAINER" >&2
  exit 1
fi

echo
echo "Logs:    docker logs $CONTAINER"
echo "Parar:   docker stop $CONTAINER"
echo "Remover: docker rm -f $CONTAINER"
