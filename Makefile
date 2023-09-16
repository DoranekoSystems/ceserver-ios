LIBS      =
INCLUDE   = -I../
TARGET    = ./ceserver
SRCDIR    = ./
SOURCES   = ceserver.mm api.mm porthelp.mm threads.mm symbols.mm lldb-auto.mm binaryio.mm
LDFLAGS += -framework Foundation
all: $(SOURCES)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -std=c++17 -lz -o $(TARGET) $(SOURCES)