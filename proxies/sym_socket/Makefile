CXX=gcc
CXXFLAGS=-Wall -Wl,-z,relro,-z,now -I../../../s2e/guest/common/include
SRC=sym_socket.c
BIN=sym_socket

all:
	$(CXX) -o $(BIN) $(SRC) $(CXXFLAGS)

clean:
	rm $(BIN)
