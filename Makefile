CFLAGS += -W -Wall -Wextra -O3 -std=gnu11

all: genmif.c
	gcc $(CFLAGS) genmif.c -o genmif

clean:
	rm -rf genmif genmif.exe

