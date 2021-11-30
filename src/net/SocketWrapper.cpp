#include <net/SocketWrapper.h>


bool SocketWrapper::sendPacket(Message* pkt, byte *buf, size_t &sendLen, size_t len, Crypto *c){
  sendLen = 0;
  bool ret = pkt->Serialize(buf, sendLen, len, c);

  if(!ret){
    std::cout << "ERROR: some error occour during Serialization " << std::endl;
    return false;
  }

  size_t size = this->Send(buf, sendLen, 0);

  /*std::cout << "data send (size = " << size << "): ";
  LOG_BUFFER(buf, sendLen);*/

  return size == sendLen;
}

bool SocketWrapper::recvPacket(byte *buf,  size_t &recvLen, size_t len, Crypto *c){
  if(len < sizeof(msglen_t) + sizeof(MessageType)){
    std::cout << "ERROR: socket buffer too small " << std::endl;
    recvLen = 0;
    return false;
  }

  unsigned int preludeSize = sizeof(msglen_t) + sizeof(MessageType);
  size_t tmpLen = 1;
  //std::cout << "waiting for message sock = " << getFd() << std::endl;
  recvLen = 0;
  while(recvLen != preludeSize && tmpLen != 0){
    tmpLen = this->Recv(buf, preludeSize - recvLen, 0);
    recvLen += tmpLen;
  }

  if(tmpLen == 0){
    recvLen = 0;
    return false;
  }

  msglen_t pktLen;

  memcpy(&pktLen, buf, sizeof(msglen_t));
  pktLen = ntohs(pktLen) + preludeSize;

  if(pktLen > 15000){
    recvLen = 0;
    std::cout << "ERROR: message too Large " << pktLen << std::endl;
    return false;
  }

  while(recvLen < pktLen && len - recvLen > 0 && tmpLen != 0){
    tmpLen = this->Recv(&buf[recvLen], pktLen - recvLen, 0);
    recvLen += tmpLen;
  }

  if(tmpLen == 0){
    recvLen = 0;
    return false;
  }
  /*std::cout << "data recv: ";
  LOG_BUFFER(buf, recvLen);*/

  return true;
}
