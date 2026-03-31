CC ?= clang

SRC := src/tahoe_patch.c
BIN_DIR := bin
BIN := $(BIN_DIR)/tahoe-patch

CFLAGS_COMMON := -std=c11 -Wall -Wextra -Wpedantic
LDFLAGS_COMMON :=

CFLAGS_DEBUG := $(CFLAGS_COMMON) -O0 -g -DDEBUG
CFLAGS_RELEASE := $(CFLAGS_COMMON) -O3 -DNDEBUG -arch arm64 -fvisibility=hidden -fno-ident -fomit-frame-pointer -flto
LDFLAGS_RELEASE := $(LDFLAGS_COMMON) -Wl,-dead_strip -flto

.PHONY: all debug release clean

all: release

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

debug: $(BIN_DIR)
	$(CC) $(CFLAGS_DEBUG) $(SRC) -o $(BIN) $(LDFLAGS_COMMON)

release: $(BIN_DIR)
	$(CC) $(CFLAGS_RELEASE) $(SRC) -o $(BIN) $(LDFLAGS_RELEASE)
	strip -S -x $(BIN)

clean:
	rm -rf $(BIN_DIR)
