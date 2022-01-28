CXX=gcc
CXXFLAGS=-g -Wall -no-pie -fno-stack-protector
SRC=main.c
BIN=aslr-nx

all:
	$(CXX) -o $(BIN) $(SRC) $(CXXFLAGS)

clean:
	rm $(BIN)
