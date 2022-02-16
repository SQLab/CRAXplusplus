CXX=gcc
CXXFLAGS=-g -Wall -I/home/aesophor/s2e/source/s2e/guest/common/include -no-pie -fno-stack-protector
SRC=main.c
BIN=b64

all:
	$(CXX) -o $(BIN) $(SRC) $(CXXFLAGS)

clean:
	rm $(BIN)
