#include <server/MessageQueue.h>


MessageQueue::MessageQueue(){
  evt = eventfd(0, EFD_SEMAPHORE);
}

bool MessageQueue::pop(){
  uint64_t data;

  sync.lock();

  q.pop();

  size_t ret = read(evt, &data, sizeof(uint64_t));

  sync.unlock();

  return ret != sizeof(uint64_t);
}

Message* MessageQueue::front(){
  Message* ret;

  sync.lock();
  ret = q.front();
  sync.unlock();

  return ret;
}

bool MessageQueue::push(Message* m){
  uint64_t data = 1;
  size_t ret = write(evt, &data, sizeof(uint64_t));

  if(ret != sizeof(uint64_t))
    return false;

  sync.lock();
  q.push(m);
  sync.unlock();

  return true;
}

size_t MessageQueue::size(){
  size_t ret;

  sync.lock();
  ret = q.size();
  sync.unlock();

  return ret;
}
