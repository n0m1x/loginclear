CXX := g++
CXXFLAGS := -lcurl
TARGET := loginclear
SRC := loginclear.cpp

release:
	$(CXX) -O3 -o $(TARGET) $(SRC) $(CXXFLAGS)

debug:
	$(CXX) -Wall -Wextra -Wpedantic -Wunused -o $(TARGET) $(SRC) $(CXXFLAGS)

experimental:
	$(CXX) -O3 -flto -funroll-loops -ffast-math -o $(TARGET) $(SRC) $(CXXFLAGS)

clean:
	rm -f $(TARGET)

install:
	install -m 755 $(TARGET) /usr/local/bin/

.PHONY: release debug experimental clean install