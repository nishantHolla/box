CC = gcc
CFLAGS = -Wall -Wextra -pedantic
INCLUDE = -Isrc/include
LIBRARY = 
SRC = 
OUT = -o out/box
MAIN = src/main.c

debug:
	$(CC) $(CFLAGS) -ggdb $(INCLUDE) $(LIBRARY) $(OUT) $(SRC) $(MAIN)

runDebug: debug
	cd out && clear && ./box $(ARGS)

release:
	$(CC) $(CFLAGS) -O3 $(INCLUDE) $(LIBRARY) $(OUT) $(SRC) $(MAIN)

runRelease: release
	cd out && clear && ./box $(ARGS)

