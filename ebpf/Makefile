CLANG ?= clang
CFLAGS ?= -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86

all: agentshield_lsm.bpf.o

agentshield_lsm.bpf.o: agentshield_lsm.bpf.c
	$(CLANG) $(CFLAGS) -c $< -o $@

clean:
	rm -f agentshield_lsm.bpf.o
