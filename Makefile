CC = gcc
CFLAGS = -Wall -Wextra -pedantic
INCLUDE = -Isrc/include
LIBRARY = -lssl -lcrypto
SRC = src/counter.c src/crypto.c src/path.c src/box.c
OUT = -o out/box
MAIN = src/main.c

# -------------------------------------------------------------------------------------------------

debug:
	$(CC) $(CFLAGS) -ggdb $(INCLUDE) $(LIBRARY) $(OUT) $(SRC) $(MAIN)

runDebug: debug
	cd out && clear && ./box $(ARGS)

memCheckDebug: debug
	cd out && clear && valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes ./box $(ARGS)

memProfileDebug: debug
	cd out && clear && valgrind --tool=massif ./box $(ARGS)

# -------------------------------------------------------------------------------------------------

test:
	$(CC) $(CFLAGS) -ggdb $(INCLUDE) $(LIBRARY) $(OUT) $(SRC) tests/*$(NAME)*.c

runTest: test
	cd out && clear && ./box $(ARGS)

memCheckTest: test
	cd out && clear && valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes ./box $(ARGS)

memProfileTest: test
	cd out && clear && valgrind --tool=massif ./box $(ARGS)

# -------------------------------------------------------------------------------------------------

release:
	$(CC) $(CFLAGS) -O3 $(INCLUDE) $(LIBRARY) $(OUT) $(SRC) $(MAIN)

runRelease: release
	cd out && clear && ./box $(ARGS)

