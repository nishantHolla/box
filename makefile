
CC=clang++
CFLAGS=-std=c++17
DEBUG_FLAGS=-O0 -g -Wall -Wextra -pedantic
RELEASE_FLAGS=-O3

SOURCE_DIR=source
INCLUDE_DIR=${SOURCE_DIR}/include
LIBRARY_DIR=${SOURCE_DIR}/library
OUTPUT_DIR=output

LIBRARIES=
SOURCE=\
	${SOURCE_DIR}/main.cpp \
	${SOURCE_DIR}/box.cpp \
	${SOURCE_DIR}/fileFlipping.cpp \
	${SOURCE_DIR}/pathFlipping.cpp \
	${SOURCE_DIR}/indexing.cpp \
	${SOURCE_DIR}/query.cpp \
	${SOURCE_DIR}/tags.cpp \
	${SOURCE_DIR}/sisIO.cpp \
	${SOURCE_DIR}/sisAuth.cpp

OUTPUT=${OUTPUT_DIR}/box

debug:
	${CC} ${SOURCE} ${CFLAGS} ${DEBUG_FLAGS} -I${INCLUDE_DIR} -L${LIBRARY_DIR} ${LIBRARIES} -o${OUTPUT}

release:
	${CC} ${SOURCE} ${CFLAGS} ${RELEASE_FLAGS} -I${INCLUDE_DIR} -L${LIBRARY_DIR} ${LIBRARIES} -o${OUTPUT}
