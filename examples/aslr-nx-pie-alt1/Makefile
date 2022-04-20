CXX=gcc
CXXFLAGS=-g -z lazy -fno-stack-protector
SRC=main.c
BIN=aslr-nx-pie-alt1

all:
	$(CXX) -o $(BIN) $(SRC) $(CXXFLAGS)

clean:
	rm $(BIN)
