LIBS      =
INCLUDE   = -I../
TARGET    = ./ceserver
TARGET_DYLIB = ./libceserver.dylib
SRCDIR    = ./
SOURCES   = ceserver.mm api.mm porthelp.mm threads.mm symbols.mm lldb-auto.mm binaryio.mm
LDFLAGS  += -framework Foundation
DYLIB_FLAGS = -dynamiclib -fPIC
all: $(SOURCES)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -std=c++17 -lz -o $(TARGET) $(SOURCES)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $(DYLIB_FLAGS) -DDYNAMIC_LIB -std=c++17 -lz -o $(TARGET_DYLIB) $(SOURCES)