CXX=g++
CXXFLAGS=-Wall -I../../source/s2e/guest/common/include
SRC=$(wildcard *.cc)
BIN=symio

all:
	$(CXX) -o $(BIN) $(SRC) $(CXXFLAGS)

clean:
	rm $(BIN)
