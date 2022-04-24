CXX=gcc
CXXFLAGS=-Wall -Wl,-z,relro,-z,now -I../../../s2e/guest/common/include
SRC=sym_env.c
BIN=sym_env

all:
	$(CXX) -o $(BIN) $(SRC) $(CXXFLAGS)

clean:
	rm $(BIN)
