#ifndef THREADQUEUE_H
#define THREADQUEUE_H

#include <net/messages.h>
#include <queue>
#include <mutex>
#include <sys/eventfd.h>
#include <unistd.h>

class MessageQueue{
  std::queue<Message*> q;
  int evt;
  std::mutex sync;
public:
  MessageQueue();

  Message* front();
  bool pop();
  bool push(Message* m);
  size_t size();

  int getFd(){ return evt; }
};

#endif
