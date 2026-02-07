# =========================================================
# ciph — Encryption Engine
# © 2026 Ankit Chaubey (@ankit-chaubey)
# https://github.com/ankit-chaubey/ciph
# Apache License 2.0
# =========================================================

.DEFAULT_GOAL := all

CC ?= cc
AR ?= ar
RM ?= rm -f

CFLAGS  = -O2 -Wall -Wextra -fPIC
LDFLAGS =
LIBS    = -lsodium

SRC = ciph.c
OBJ = ciph.o
HDR = ciph.h

UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Linux)
    SHARED = libciph.so
endif

ifeq ($(UNAME_S),Darwin)
    SHARED = libciph.dylib
    LDFLAGS += -dynamiclib
endif

ifeq ($(findstring MINGW,$(UNAME_S)),MINGW)
    SHARED = ciph.dll
    LDFLAGS += -shared
endif

STATIC = libciph.a

check:
	@pkg-config --exists libsodium || ( \
		echo "libsodium not found."; \
		echo ""; \
		echo "Install it using:"; \
		echo "  Debian/Ubuntu/Termux: sudo apt install libsodium-dev"; \
		echo "  Arch: sudo pacman -S libsodium"; \
		echo "  Fedora: sudo dnf install libsodium-devel"; \
		echo "  macOS: brew install libsodium"; \
		exit 1 \
	)

all: check shared static

shared: $(SHARED)

static: $(STATIC)

$(OBJ): $(SRC) $(HDR)
	$(CC) $(CFLAGS) -c $(SRC) -o $(OBJ)

$(SHARED): $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -shared $(OBJ) -o $(SHARED) $(LIBS)

$(STATIC): $(OBJ)
	$(AR) rcs $(STATIC) $(OBJ)

clean:
	$(RM) $(OBJ) $(SHARED) $(STATIC)

install:
	install -Dm755 $(SHARED) /usr/local/lib/$(SHARED)
	install -Dm644 $(HDR) /usr/local/include/ciph.h

.PHONY: all check shared static clean install
