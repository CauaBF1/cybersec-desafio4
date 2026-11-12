#!/usr/bin/env bash
# Executa a matriz do experimento, a regressao e os smoke tests.
set -Eeuo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$HERE/.." && pwd)"
CHAL_DIR="$ROOT/pwnymalloc/challenge"
BUILD="$HERE/build"
LOG_DIR="$ROOT/evidencias"
LOG="$LOG_DIR/experimento-causa-raiz.txt"

mkdir -p "$LOG_DIR" "$BUILD"
: > "$LOG"
exec > >(tee -a "$LOG") 2>&1
ulimit -c 0

fail=0

run_test() {
    local bin="$1"
    local name="$2"
    local expect="$3"   # 0 = deve passar; 1 = deve falhar
    local label="$4"
    local log="$LOG_DIR/experimento-regressao-${label}-${name}.log"
    local rc

    if bash -c '"$1" "$2"; exit $?' _ "$bin" "$name" > "$log" 2>&1; then
        rc=0
    else
        rc=$?
    fi

    if { [ "$rc" -eq 0 ] && [ "$expect" -eq 0 ]; } || \
       { [ "$rc" -ne 0 ] && [ "$expect" -eq 1 ]; }; then
        echo "[OK] $label/$name (exit=$rc)"
    else
        echo "[FALHOU] $label/$name (esperado exit=$expect, obtido $rc)"
        tail -20 "$log" || true
        fail=1
    fi
}

smoke() {
    local nome="$1"
    local entrada="$2"
    local padrao="$3"
    local log="$LOG_DIR/experimento-smoke-$nome.log"

    if (cd "$CHAL_DIR" && printf '%b' "$entrada" | "$BUILD/chal_hardened") \
            > "$log" 2>&1 && grep -q "$padrao" "$log"; then
        echo "[OK] smoke/$nome"
    else
        echo "[FALHOU] smoke/$nome"
        tail -20 "$log" || true
        fail=1
    fi
}

echo "============================================================"
echo " Experimento de causa raiz do pwnymalloc"
echo "============================================================"
echo

echo "--- build ---"
make -C "$HERE" clean >/dev/null
make -C "$HERE" all
make -C "$HERE" patches >/dev/null
echo

echo "--- matriz de ataque ---"
if ! python3 "$HERE/harness_exploit.py" \
        --build-dir "$BUILD" \
        --chal-dir "$CHAL_DIR" \
        --log-dir "$LOG_DIR"; then
    fail=1
fi
echo

echo "--- regressao funcional ---"
for t in basico prev_livre split reuso estresse double_free ponteiro_invalido; do
    run_test "$BUILD/test_vuln" "$t" 0 vuln
    run_test "$BUILD/test_naive" "$t" 0 naive
    run_test "$BUILD/test_hardened" "$t" 0 hardened
done

# O split tambem le um tag que cai em dados do usuario. Este teste prova que o
# problema existe nos dois builds fracos e desaparece no hardened.
run_test "$BUILD/test_vuln" cauda_envenenada 1 vuln
run_test "$BUILD/test_naive" cauda_envenenada 1 naive
run_test "$BUILD/test_hardened" cauda_envenenada 0 hardened
echo

echo "--- smoke tests do servico endurecido ---"
smoke menu '2\n5\n' 'complaint database is currently down'
smoke refund '3\n0\nhello\n4\n0\n5\n' 'refund request has been denied'
echo

echo "--- fontes originais intactas ---"
if ! make -C "$HERE" check-fonte; then
    fail=1
fi
echo

if [ "$fail" -eq 0 ]; then
    echo "RESUMO: EXPERIMENTO OK"
else
    echo "RESUMO: EXPERIMENTO FALHOU"
fi

exit "$fail"
