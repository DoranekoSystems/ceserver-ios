#include "binaryio.h"
#include "api.h"

ssize_t recvall(int s, void *buf, size_t size, int flags) {
  ssize_t totalreceived = 0;
  ssize_t sizeleft = size;
  unsigned char *buffer = (unsigned char *)buf;

  // enter recvall
  flags = flags | MSG_WAITALL;

  while (sizeleft > 0) {
    ssize_t i = recv(s, &buffer[totalreceived], sizeleft, flags);

    if (i == 0) {
      debug_log("recv returned 0\n");
      return i;
    }

    if (i == -1) {
      debug_log("recv returned -1\n");
      if (errno == EINTR) {
        debug_log("errno = EINTR\n");
        i = 0;
      } else {
        debug_log("Error during recvall: %d. errno=%d\n", (int)i, errno);
        return i; // read error, or disconnected
      }
    }

    totalreceived += i;
    sizeleft -= i;
  }

  // leave recvall
  return totalreceived;
}

ssize_t sendall(int s, void *buf, size_t size, int flags) {
  ssize_t totalsent = 0;
  ssize_t sizeleft = size;
  unsigned char *buffer = (unsigned char *)buf;

  while (sizeleft > 0) {
    ssize_t i = send(s, &buffer[totalsent], sizeleft, flags);

    if (i == 0) {
      return i;
    }

    if (i == -1) {
      if (errno == EINTR)
        i = 0;
      else {
        debug_log("Error during sendall: %d. errno=%d\n", (int)i, errno);
        return i;
      }
    }

    totalsent += i;
    sizeleft -= i;
  }

  return totalsent;
}