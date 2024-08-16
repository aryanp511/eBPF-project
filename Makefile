CC = clang
CFLAGS = -O2 -Wall -target bpf
BPFTOOL = bpftool

all: xdp_program.o

xdp_program.o: xdp_program.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f xdp_program.o

.PHONY: all clean
