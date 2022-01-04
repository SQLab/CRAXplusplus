CXX=gcc
CXXFLAGS=-Wall -I../../guest/common/include
SRC=$(wildcard *.c)
BIN=sym_stdin

all:
	$(CXX) -o $(BIN) $(SRC) $(CXXFLAGS)

clean:
	rm $(BIN)
