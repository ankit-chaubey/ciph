# =========================================================
# ciph — Encryption Engine
# © 2026 Ankit Chaubey (@ankit-chaubey)
# https://github.com/ankit-chaubey/ciph
# Apache License 2.0
# =========================================================

.DEFAULT_GOAL := all

CC      ?= cc
AR      ?= ar
RM      ?= rm -f
PREFIX  ?= /usr/local

CFLAGS  = -O2 -Wall -Wextra -fPIC
LDFLAGS =
LIBS    = -lsodium

SRC = ciph.c
OBJ = ciph.o
HDR = ciph.h

UNAME_S := $(shell uname -s)

# -------------------------
# Platform detection
# -------------------------

ifeq ($(UNAME_S),Linux)
    SHARED  = libciph.so
    LDFLAGS += -shared -Wl,-soname,libciph.so
endif

ifeq ($(UNAME_S),Darwin)
    SHARED  = libciph.dylib
    LDFLAGS += -dynamiclib
endif

ifeq ($(findstring MINGW,$(UNAME_S)),MINGW)
    SHARED  = libciph.dll
    LDFLAGS += -shared
endif

STATIC = libciph.a

# -------------------------
# Targets
# -------------------------

all: check shared static

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

shared: $(SHARED)

static: $(STATIC)

# -------------------------
# Build rules
# -------------------------

$(OBJ): $(SRC) $(HDR)
	$(CC) $(CFLAGS) -c $(SRC) -o $(OBJ)

$(SHARED): $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJ) -o $(SHARED) $(LIBS)

$(STATIC): $(OBJ)
	$(AR) rcs $(STATIC) $(OBJ)

# -------------------------
# Install / Clean
# -------------------------

install:
	install -Dm755 $(SHARED) $(PREFIX)/lib/$(SHARED)
	install -Dm644 $(HDR) $(PREFIX)/include/ciph.h

clean:
	$(RM) $(OBJ) $(SHARED) $(STATIC)

# -------------------------
# Debug helper
# -------------------------

print-config:
	@echo "OS      : $(UNAME_S)"
	@echo "CC      : $(CC)"
	@echo "CFLAGS  : $(CFLAGS)"
	@echo "LDFLAGS : $(LDFLAGS)"
	@echo "SHARED  : $(SHARED)"
	@echo "PREFIX  : $(PREFIX)"

.PHONY: all check shared static install clean print-config
