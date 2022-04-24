CXX=gcc
CXXFLAGS=-g -z lazy -no-pie -fno-stack-protector
SRC=main.c
BIN=pwnable-kr-bof

all:
	$(CXX) -o $(BIN) $(SRC) $(CXXFLAGS)

clean:
	rm $(BIN)
