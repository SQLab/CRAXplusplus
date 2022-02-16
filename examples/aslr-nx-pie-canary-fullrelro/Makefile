CXX=gcc
CXXFLAGS=-g -z now
SRC=main.c
BIN=aslr-nx-pie-canary-fullrelro

all:
	$(CXX) -o $(BIN) $(SRC) $(CXXFLAGS)

clean:
	rm $(BIN)
