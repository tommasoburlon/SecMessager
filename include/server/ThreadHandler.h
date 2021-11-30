#ifndef THREADCHANNEL_H
#define THREADCHANNEL_H

#include <crypto/Crypto.h>
#include <net/messages.h>
#include <net/SocketWrapper.h>
#include <server/MessageQueue.h>
#include <string.h>
#include <iostream>
#include <dirent.h>
#include <vector>
#include <map>
#include <unordered_map>
#include <thread>
#include <mutex>

struct threadData;

struct user_t{
  username_t name;
  size_t id;
  EVP_PKEY* publicKey;
};

enum threadState{
  INIT,
  ZOMBIE,
  ONLINE,
  WAITING,
  CHATTING
};

//class to handle the inter thread commmunication
class ThreadHandler{
  size_t maxId;

  std::map<std::string, threadData*> onlineUser;
  std::unordered_map<size_t, threadData*> threadTable;

  // data structure initialize at the beginning of the program
  std::unordered_map<std::string, user_t*> name2user;
  std::vector<user_t*> userVector;
  std::mutex sync;
public:

  ThreadHandler() : maxId(1) {};

  ~ThreadHandler();

  size_t getThreadByUser(std::string username);

  bool load(const char* path, Crypto *c);

  user_t* getUserByName(std::string username);

  user_t* getUserById(size_t id);

  size_t insertNewThread(threadData* data);

  bool sendMessageTo(Message* m, size_t id);

  bool removeThread(size_t id);

  bool setUserOnline(std::string name, threadData* refThread);

  bool setUserOffline(std::string name);

  usernamelist_t getList(username_t user, uint32_t offset);

  bool isUserOnline(std::string name);

  bool startChatting(threadData* thread1, size_t id);
};

struct threadData{
  size_t id;
  std::thread th;
  MessageQueue mess;
  SocketWrapper sock;
  Crypto crypto;
  threadState state;
  username_t account;

  //read-only data stracture (no lock required)
  X509* cert;
  EVP_PKEY* prvkey;

  ThreadHandler *channel;

  //HEAP allocated data structure
  symkey_t key;              // symmetric key
  EVP_PKEY *dh_pub, *dh_key; // ECDH

  ~threadData(){
    delete[] key.data;
  }

  threadData(){
    key.data = nullptr;
  }
};

#endif
