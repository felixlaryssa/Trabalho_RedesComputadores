CC = gcc

CFLAGS = -Wall -Wextra -Wpedantic -std=c11

TARGET = meu_cliente

SRC = src/main.c \
      src/dns_request.c

all:
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET)

clean:
	rm -f $(TARGET)

run:
	./$(TARGET) unb.br 8.8.8.8
	