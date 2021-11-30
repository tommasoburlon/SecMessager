#ifndef MESSAGE_H
#define MESSAGE_H

#include <cstring>
#include <cmath>
#include <algorithm>
#include <openssl/x509.h>
#include <var.h>
#include <crypto/Crypto.h>
#include <arpa/inet.h>
#include <iostream>

enum MessageType{
  RCQCERT,
  SNDCERT,
  ACKCERT,

  RCQLIST,
  SNDLIST,

  RCQCONN,
  RESCONN,
  SNDPUBK,
  AUTHCLN,

  SECMESG,
  INFMESG,

  NUMTYPES,
  NOTYPE,
  SIGNED = 0b10000000,
};

enum InfoType{
  DEFAULT,
  LOGOFF,
  NOCLIENT,
  NORCQ,
  WRGKEY,
  QUIT,
  PING
};

class Message{
public:
  Message(){};
  virtual ~Message(){};

  // methods to Serialize or Deserialize a Message
  static Message* fromBuffer(byte *buf, size_t& size, size_t max, Crypto *crypto = nullptr);

  bool Serialize(byte *buf, size_t &finalSize, size_t max, Crypto *crypto = nullptr);
  bool Deserialize(byte *buf, size_t &finalSize, size_t maxSize, Crypto *crypto = nullptr);

  // methods to Decrypt or Autheniticate a buffer containing a Serialize Message
  bool Decrypt(byte *buf, size_t &size, size_t maxSize, Crypto *crypto = nullptr);
  static bool Authenticate(byte *buf, size_t size, size_t maxSize, Crypto *crypto);

  // virtual methods to Serialize/Deserialize data insidea concrete Message
  virtual bool DataToBuffer(byte *buf, size_t max, size_t &finalSize, Crypto *c) = 0;
  virtual bool BufferToData(byte *buf, size_t max, size_t &finalSize, Crypto *c) = 0;

  virtual MessageType getType() = 0;
};


class RcqCertMessage : public Message{
  nonce_t nonce;
  dh_key_t dh_public;
public:
  ~RcqCertMessage(){};

  //getter/setter methods
  nonce_t getNonce(){ return nonce; };
  RcqCertMessage& setNonce(nonce_t _nonce){ nonce = _nonce; return *this; };

  EVP_PKEY* getDHKey(){ return dh_public.data; };
  RcqCertMessage& setDHKey(EVP_PKEY* _dh_public){ dh_public.data = _dh_public; return *this; };

  // concrete definition of virtual methods
  bool DataToBuffer(byte *buf, size_t max, size_t &finalSize, Crypto *c);
  bool BufferToData(byte *buf, size_t max, size_t &finalSize, Crypto *c);
  MessageType getType(){ return RCQCERT; }
};

class SndCertMessage : public Message{
  X509* cert;
  nonce_t nonce;
  dh_key_t dh_public;
public:
  ~SndCertMessage(){};

  //getter/setter methods
  X509* getCert(){ return cert; };
  SndCertMessage& setCert(X509* _cert){ cert = _cert; return *this;};

  nonce_t getNonce(){ return nonce; };
  SndCertMessage& setNonce(nonce_t _nonce){ nonce = _nonce; return *this;};

  EVP_PKEY* getDHKey(){ return dh_public.data; };
  SndCertMessage& setDHKey(EVP_PKEY* _dh_public){ dh_public.data = _dh_public; return *this;};

  // concrete definition of virtual methods
  bool DataToBuffer(byte *buf, size_t max, size_t &finalSize, Crypto *c);
  bool BufferToData(byte *buf, size_t max, size_t &finalSize, Crypto *c);
  MessageType getType(){ return SNDCERT; }
};

class AckCertMessage : public Message{
  username_t user;
  nonce_t nonce;
public:
  ~AckCertMessage(){};

  //getter/setter methods
  username_t getUsername(){ user.data[USERNAME_SIZE - 1] = '\0'; return user; };
  AckCertMessage& setUsername(username_t _user){ memcpy(user.data, _user.data, USERNAME_SIZE); return *this;};

  nonce_t getNonce(){ return nonce; };
  AckCertMessage& setNonce(nonce_t _nonce){ nonce = _nonce; return *this;};

  // concrete definition of virtual methods
  bool DataToBuffer(byte *buf, size_t max, size_t &finalSize, Crypto *c);
  bool BufferToData(byte *buf, size_t max, size_t &finalSize, Crypto *c);
  MessageType getType(){ return ACKCERT; }
};

class RcqListMessage : public Message{
  username_t user;
  uint32_t offset;
public:
  ~RcqListMessage(){};

  //getter/setter methods
  username_t getUsername(){ user.data[USERNAME_SIZE - 1] = '\0'; return user; };
  void setUsername(username_t _user){  memcpy(user.data, _user.data, USERNAME_SIZE);  };

  uint32_t getOffset(){ return offset; };
  void setOffset(uint32_t _offset){ offset = _offset; };

  // concrete definition of virtual methods
  bool DataToBuffer(byte *buf, size_t max, size_t &finalSize, Crypto *c);
  bool BufferToData(byte *buf, size_t max, size_t &finalSize, Crypto *c);
  MessageType getType(){ return RCQLIST; }
};

class SndListMessage : public Message{
  usernamelist_t list;
public:
  ~SndListMessage(){};

  //getter/setter methods
  usernamelist_t getList(){ return list; };
  void setList(usernamelist_t _list){ list = _list; };

  // concrete definition of virtual methods
  bool DataToBuffer(byte *buf, size_t max, size_t &finalSize, Crypto *c);
  bool BufferToData(byte *buf, size_t max, size_t &finalSize, Crypto *c);
  MessageType getType(){ return SNDLIST; }
};

class RcqConnMessage : public Message{
  username_t user;
public:
  ~RcqConnMessage(){};

  //getter/setter methods
  username_t getUsername(){ user.data[USERNAME_SIZE - 1] = '\0'; return user; };
  void setUsername(username_t _user){ memcpy(user.data, _user.data, USERNAME_SIZE); };

  // concrete definition of virtual methods
  bool DataToBuffer(byte *buf, size_t max, size_t &finalSize, Crypto *c);
  bool BufferToData(byte *buf, size_t max, size_t &finalSize, Crypto *c);
  MessageType getType(){ return RCQCONN; }
};

class ResConnMessage : public Message{
  bool accepted;
  username_t user;
public:
  ResConnMessage() :  accepted(false) {};
  ~ResConnMessage(){};

  //getter/setter methods
  bool isAccepted(){ return accepted; };
  void accept(){ accepted = true; };

  username_t getUsername(){ user.data[USERNAME_SIZE - 1] = '\0'; return user; };
  void setUsername(username_t _user){ memcpy(user.data, _user.data, USERNAME_SIZE); };

  // concrete definition of virtual methods
  bool DataToBuffer(byte *buf, size_t max, size_t &finalSize, Crypto *c);
  bool BufferToData(byte *buf, size_t max, size_t &finalSize, Crypto *c);
  MessageType getType(){ return RESCONN; }
};

class SndPubkMessage : public Message{
  ec_key_t pubkey;
  bool first;
public:
  ~SndPubkMessage(){};

  //getter/setter methods
  EVP_PKEY* getKey(){ return pubkey.data; };
  void setKey(EVP_PKEY* _key){ pubkey.data = _key; };

  bool isFirst(){ return first; };
  void setFirst(bool _first){ first = _first; };

  // concrete definition of virtual methods
  bool DataToBuffer(byte *buf, size_t max, size_t &finalSize, Crypto *c);
  bool BufferToData(byte *buf, size_t max, size_t &finalSize, Crypto *c);
  MessageType getType(){ return SNDPUBK; }
};

class AuthClnMessage : public Message{
  dh_key_t dh_key;
  nonce_t nonce;
public:
  ~AuthClnMessage(){};

  //getter/setter methods
  EVP_PKEY* getDHKey(){ return dh_key.data; };
  void setDHKey(EVP_PKEY* _dh_key){ dh_key.data = _dh_key; };

  nonce_t getNonce(){ return nonce; };
  void setNonce(nonce_t _nonce){ nonce = _nonce; };

  // concrete definition of virtual methods
  bool DataToBuffer(byte *buf, size_t max, size_t &finalSize, Crypto *c);
  bool BufferToData(byte *buf, size_t max, size_t &finalSize, Crypto *c);
  MessageType getType(){ return AUTHCLN; }
};

class SecMesgMessage : public Message{
  buffer_t buf;
public:
  SecMesgMessage(){ buf.data = nullptr; }
  ~SecMesgMessage(){ if(buf.data){delete[] buf.data;}};

  //getter/setter methods
  buffer_t getData(){ return buf; };
  Message* getMessage(byte* buffer, size_t &size, size_t maxSize, Crypto *c){
    if(buf.size > maxSize)
      return NULL;
    memcpy(buffer, buf.data, buf.size);
    size = buf.size;
    return Message::fromBuffer(buffer, size, maxSize, c);
  }

  bool setMessage(Message *m, byte* buffer, size_t maxSize, Crypto *c){
    size_t bufferSize;
    bool err = m->Serialize(buffer, bufferSize, maxSize, c);
    if(!err) return err;
    setData(buffer, bufferSize);
    return true;
  }

  void setData(byte* _buf, size_t size){
    if(buf.data){delete[] buf.data;}
    buf.data = new byte[size];
    buf.size = size;
    memcpy(buf.data, _buf, size);
  };

  // concrete definition of virtual methods
  bool DataToBuffer(byte *buf, size_t max, size_t &finalSize, Crypto *c);
  bool BufferToData(byte *buf, size_t max, size_t &finalSize, Crypto *c);
  MessageType getType(){ return SECMESG; }
};

class InfMesgMessage : public Message{
  InfoType info;
public:
  ~InfMesgMessage(){};

  //getter/setter methods
  InfoType getInfo(){ return info; };
  void setInfo(InfoType _info){ info = _info; };

  // concrete definition of virtual methods
  bool DataToBuffer(byte *buf, size_t max, size_t &finalSize, Crypto *c);
  bool BufferToData(byte *buf, size_t max, size_t &finalSize, Crypto *c);
  MessageType getType(){ return INFMESG; }
};

#endif
