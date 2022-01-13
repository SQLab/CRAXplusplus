CXX=gcc
CXXFLAGS=-Wall -Wl,-z,relro,-z,now -I../../guest/common/include
SRC=sym_file.c
BIN=sym_file

all:
	$(CXX) -o $(BIN) $(SRC) $(CXXFLAGS)
clean:
	rm $(BIN)
	