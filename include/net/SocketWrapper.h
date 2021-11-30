#ifndef SOCKETWRAPPER_H
#define SOCKETWRAPPER_H

#include <sys/socket.h>
#include <crypto/Crypto.h>
#include <unistd.h>
#include <cmath>
#include "messages.h"

class SocketWrapper{
  int fd;
public:
  SocketWrapper(int _fd = 0): fd(_fd) {};

  void init(int domain = AF_INET, int type = SOCK_STREAM, int protocol = 0){ fd = socket(domain, type, protocol); };
  void settimeout(uint32_t milliseconds){
    struct timeval tv;
    tv.tv_sec  = milliseconds / 1000;
    tv.tv_usec = (milliseconds % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
  }

  int Bind(const struct sockaddr *addr, socklen_t addrlen){return bind(fd, addr, addrlen); };
  int Listen(int backlog){ return listen(fd, backlog); };
  int Setsockopt(int level, int optname, const void *optval, socklen_t optlen){ return setsockopt(fd, level, optname, optval, optlen); };
  SocketWrapper Accept(struct sockaddr *addr, socklen_t *addrlen){ return SocketWrapper(accept(fd, addr, addrlen)); };
  int Connect(const struct sockaddr *addr, socklen_t addrlen){ return connect(fd, addr, addrlen); };

  size_t Send(const void* buf, size_t len, int flags){return send(fd, buf, len, flags); };
  size_t Recv(void* buf, size_t len, int flags){ return recv(fd, buf, len, flags); };

  bool recvPacket(byte *buf, size_t &recvLen, size_t len, Crypto *c = nullptr);
  bool sendPacket(Message* pkt, byte *buf, size_t &sendLen, size_t len, Crypto *c = nullptr);

  void Close(){ close(fd); }
  int getFd(){ return fd; }
};

#endif
