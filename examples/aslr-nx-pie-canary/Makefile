CXX=gcc
CXXFLAGS=-g -z lazy
SRC=main.c
BIN=aslr-nx-pie-canary

all:
	$(CXX) -o $(BIN) $(SRC) $(CXXFLAGS)

clean:
	rm $(BIN)
