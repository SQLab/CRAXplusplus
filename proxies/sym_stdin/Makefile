CXX=gcc
CXXFLAGS=-Wall -Wl,-z,relro,-z,now -I../../../s2e/guest/common/include
SRC=sym_stdin.c
BIN=sym_stdin

all:
	$(CXX) -o $(BIN) $(SRC) $(CXXFLAGS)

clean:
	rm $(BIN)
