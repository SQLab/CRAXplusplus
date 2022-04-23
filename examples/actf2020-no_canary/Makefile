CXX=gcc
CXXFLAGS=-g -z lazy -no-pie -fno-stack-protector
SRC=main.c
BIN=actf2020-no_canary

all:
	$(CXX) -o $(BIN) $(SRC) $(CXXFLAGS)

clean:
	rm $(BIN)
