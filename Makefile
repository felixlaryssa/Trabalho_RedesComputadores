CC := gcc
CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -Werror
CPPFLAGS := -Isrc
BUILD_DIR := build
TEST_BIN := $(BUILD_DIR)/test_udp_client

.PHONY: all test clean

all: test

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(TEST_BIN): src/udp_client.c tests/test_udp_client.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ -o $@

test: $(TEST_BIN)
	./$(TEST_BIN)

clean:
	rm -f $(TEST_BIN)
	rmdir $(BUILD_DIR) 2>/dev/null || true
