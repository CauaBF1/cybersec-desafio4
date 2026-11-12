CC      ?= gcc
CFLAGS  ?= -Wall -Wextra -O0 -g -I ../pwnymalloc/challenge

CHAL_DIR := ../pwnymalloc/challenge
BUILD    := build
PATCHES  := patches
ALLOC    := alloc_hardened.c
POC      := poc_causa_raiz.c
TEST     := test_regressao.c

.PHONY: all clean run patches check-fonte

all: $(BUILD)/chal_vuln $(BUILD)/chal_naive $(BUILD)/chal_hardened \
     $(BUILD)/poc_vuln $(BUILD)/poc_naive $(BUILD)/poc_hardened \
     $(BUILD)/test_vuln $(BUILD)/test_naive $(BUILD)/test_hardened

$(BUILD):
	mkdir -p $(BUILD)

# ---- servico local: main.c + allocator -------------------------------------
$(BUILD)/chal_vuln: $(CHAL_DIR)/main.c $(CHAL_DIR)/alloc.c $(CHAL_DIR)/alloc.h | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $(CHAL_DIR)/main.c $(CHAL_DIR)/alloc.c

$(BUILD)/chal_naive: $(CHAL_DIR)/main.c $(ALLOC) $(CHAL_DIR)/alloc.h | $(BUILD)
	$(CC) $(CFLAGS) -DPWN_BTAG_CHECK_ONLY -DPWN_DEBUG -o $@ \
		$(CHAL_DIR)/main.c $(ALLOC)

$(BUILD)/chal_hardened: $(CHAL_DIR)/main.c $(ALLOC) $(CHAL_DIR)/alloc.h | $(BUILD)
	$(CC) $(CFLAGS) -DPWN_DEBUG -o $@ $(CHAL_DIR)/main.c $(ALLOC)

# ---- ataque no nivel do allocator ------------------------------------------
$(BUILD)/poc_vuln: $(POC) $(CHAL_DIR)/alloc.c $(CHAL_DIR)/alloc.h | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $(POC) $(CHAL_DIR)/alloc.c

$(BUILD)/poc_naive: $(POC) $(ALLOC) $(CHAL_DIR)/alloc.h | $(BUILD)
	$(CC) $(CFLAGS) -DPWN_BTAG_CHECK_ONLY -DPWN_DEBUG -o $@ $(POC) $(ALLOC)

$(BUILD)/poc_hardened: $(POC) $(ALLOC) $(CHAL_DIR)/alloc.h | $(BUILD)
	$(CC) $(CFLAGS) -DPWN_DEBUG -o $@ $(POC) $(ALLOC)

# ---- regressao funcional ----------------------------------------------------
$(BUILD)/test_vuln: $(TEST) $(CHAL_DIR)/alloc.c $(CHAL_DIR)/alloc.h | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $(TEST) $(CHAL_DIR)/alloc.c

$(BUILD)/test_naive: $(TEST) $(ALLOC) $(CHAL_DIR)/alloc.h | $(BUILD)
	$(CC) $(CFLAGS) -DPWN_BTAG_CHECK_ONLY -DPWN_DEBUG -o $@ $(TEST) $(ALLOC)

$(BUILD)/test_hardened: $(TEST) $(ALLOC) $(CHAL_DIR)/alloc.h | $(BUILD)
	$(CC) $(CFLAGS) -DPWN_DEBUG -o $@ $(TEST) $(ALLOC)

# ---- utilitarios ------------------------------------------------------------
$(PATCHES)/alloc_hardened.diff: $(CHAL_DIR)/alloc.c $(ALLOC)
	mkdir -p $(PATCHES)
	diff -u $(CHAL_DIR)/alloc.c $(ALLOC) > $@ || true

patches: $(PATCHES)/alloc_hardened.diff

run: all
	bash run_experimento.sh

check-fonte:
	@git diff --exit-code -- $(CHAL_DIR)/alloc.c $(CHAL_DIR)/alloc.h \
		$(CHAL_DIR)/chal $(CHAL_DIR)/flag.txt && \
		echo "OK: allocator/binario/flag originais intactos"

clean:
	rm -rf $(BUILD)
