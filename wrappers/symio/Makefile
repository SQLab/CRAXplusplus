CXX=g++
CXXFLAGS=-Wall -I../../guest/common/include
SRC=$(wildcard *.cc)
BIN=symio

all:
	$(CXX) -o $(BIN) $(SRC) $(CXXFLAGS)

clean:
	rm $(BIN)
