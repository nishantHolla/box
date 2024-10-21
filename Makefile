CC = gcc
CFLAGS = -Wall -Wextra -pedantic
INCLUDE = -Isrc/include
LIBRARY = 
SRC = src/counter.c
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

test:
	$(CC) $(CFLAGS) -ggdb $(INCLUDE) $(LIBRARY) $(OUT) $(SRC) tests/*$(NAME)*.c

runTest: test
	cd out && clear && ./box $(ARGS)

memCheck: debug
	cd out && clear && valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes ./box $(ARGS)

memCheckTest: test
	cd out && clear && valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes ./box $(ARGS)
