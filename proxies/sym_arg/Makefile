CXX=gcc
CXXFLAGS=-Wall -Wl,-z,relro,-z,now -I../../../s2e/guest/common/include
SRC=sym_arg.c
BIN=sym_arg

all:
	$(CXX) -o $(BIN) $(SRC) $(CXXFLAGS)

clean:
	rm $(BIN)
