#ifndef BINARYIO_H
#define BINARYIO_H

#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <zlib.h>

#include <thread>

ssize_t recvall(int s, void *buf, size_t size, int flags);
ssize_t sendall(int s, void *buf, size_t size, int flags);

class BinaryReader
{
private:
    int socket_fd;

public:
    BinaryReader(int socket_fd) : socket_fd(socket_fd) {}

    template <typename T>
    T Read();
};

class BinaryWriter
{
private:
    int socket_fd;

public:
    BinaryWriter(int socket_fd) : socket_fd(socket_fd) {}

    template <typename T>
    void Write(T value);
};

template <typename T>
T BinaryReader::Read()
{
    T value;
    recvall(socket_fd, &value, sizeof(T), MSG_WAITALL);
    return value;
}

template <typename T>
void BinaryWriter::Write(T value)
{
    sendall(socket_fd, &value, sizeof(T), MSG_WAITALL);
}

#endif