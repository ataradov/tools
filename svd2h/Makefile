UNAME := $(shell uname)

CFLAGS += -W -Wall -Wextra --std=gnu11 -O3
CFLAGS += -fno-diagnostics-show-caret
CFLAGS += -I.

SRCS += \
  xml.c \
  svd.c \
  gen.c \
  os_common.c \
  main.c \

HDRS += \
  xml.h \
  svd.h \
  gen.h \
  os_common.h \
  cores.h \

ifeq ($(UNAME), Linux)
  BIN = svd2h
else
  BIN = svd2h.exe
endif

all: $(BIN)

$(BIN): $(SRCS) $(HDRS)
	gcc $(CFLAGS) $(SRCS) -o $(BIN) $(LDFLAGS)

clean:
	rm -f $(BIN)

