LIBS      =
INCLUDE   = -I../
TARGET    = ./ceserver
SRCDIR    = ./
SOURCES   = ceserver.mm api.mm porthelp.mm threads.mm symbols.mm
LDFLAGS += -framework Foundation
all: $(SOURCES)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -std=c++11 -lz -o $(TARGET) $(SOURCES)