CXX=gcc
CXXFLAGS=-g -Wall -no-pie
SRC=main.c
BIN=aslr-nx-canary

all:
	$(CXX) -o $(BIN) $(SRC) $(CXXFLAGS)

clean:
	rm $(BIN)
