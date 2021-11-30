#include <server/ThreadHandler.h>

ThreadHandler::~ThreadHandler(){
  for(auto itr : userVector){
    OPENSSL_free(itr->publicKey);
    delete itr;
  }

  for(auto itr : threadTable){
    delete itr.second;
  }
}

bool ThreadHandler::load(const char* path, Crypto *c){
  DIR *dir;
  struct dirent *ent;
  char buf[PATH_MAX + 1];
  const char *pubkeys = path;
  user_t *newUser;
  size_t counter = 0;

  std::cout << "Loading keys...." << std::endl;
  // opend the directory that contains every public key
  if ((dir = opendir (pubkeys)) != NULL) {

    //read every file inside of that
    while ((ent = readdir (dir)) != NULL) {

      // "." ".." "files" do not count
      if(strcmp(ent->d_name, ".") && strcmp(ent->d_name, "..")){

        //copy the full address to buf
        memcpy(buf, pubkeys, strlen(pubkeys));
        memcpy(&buf[strlen(pubkeys)], ent->d_name, strlen(ent->d_name) + 1);

        //try to load the new key
        EVP_PKEY* key = c->loadPubKeyFromFile(buf);

        if(key == NULL){
          std::cout << "ERROR: impossble to load key : " << buf << std::endl;
        }else{
          std::cout << "key loaded: " << buf << std::endl;
          size_t i = 0;

          //read the name of the file without the format to get the username
          while(ent->d_name[i] != '.' && ent->d_name[i] != '\0'){i++;};
          ent->d_name[i] = '\0';

          newUser = new user_t;
          newUser->publicKey = key;
          newUser->id = counter;
          memcpy(newUser->name.data, ent->d_name, i + 1);

          std::cout << "username: " << newUser->name.data << std::endl;
          name2user.insert(std::pair<std::string, user_t*>(std::string(newUser->name.data), newUser));
          userVector.push_back(newUser);
          counter++;
        }
      }
    }
    closedir (dir);

    std::cout << ".... keys loaded" << std::endl;
  } else {
    return false;
  }

  return true;
}

user_t* ThreadHandler::getUserByName(std::string username){
  auto itr = name2user.find(username);
  if(itr == name2user.end())
    return nullptr;
  return itr->second;
}

user_t* ThreadHandler::getUserById(size_t id){
  if(id < 0 || id >= userVector.size())
    return nullptr;
  return userVector[id];
}

size_t ThreadHandler::insertNewThread(threadData* data){
  size_t id;

  sync.lock();
  id = maxId;
  threadTable.insert(std::pair<size_t, threadData*>(id, data));
  maxId++;
  sync.unlock();

  return id;
}

bool ThreadHandler::sendMessageTo(Message* m, size_t id){
  bool response = true;

  sync.lock();
  auto itr = threadTable.find(id);
  if(itr == threadTable.end())
    response = false;
  else
    itr->second->mess.push(m);
  sync.unlock();

  return response;
}

bool ThreadHandler::removeThread(size_t id){
  bool response = true;

  sync.lock();
  auto itr = threadTable.find(id);
  if(itr == threadTable.end())
    response = false;
  else{
    threadData *toDelete = itr->second;
    threadTable.erase(id);
    delete toDelete;
  }
  sync.unlock();

  return response;
}

bool ThreadHandler::setUserOnline(std::string name, threadData* refThread){
  bool response = true;

  sync.lock();
  auto itr = onlineUser.find(name);
  if(itr != onlineUser.end())
    response = false;
  else
    onlineUser.insert(std::pair<std::string, threadData*>(name, refThread));
  sync.unlock();

  return response;
}

bool ThreadHandler::setUserOffline(std::string name){
  bool response = true;

  sync.lock();
  auto itr = onlineUser.find(name);
  if(itr == onlineUser.end())
    response = false;
  else
    onlineUser.erase(name);
  sync.unlock();

  return response;
}

usernamelist_t ThreadHandler::getList(username_t user, uint32_t offset){
  size_t index = 0;
  usernamelist_t list;
  std::string first_user, last_user;

  first_user = std::string(user.data);
  last_user  = std::string(user.data) + (char)255;

  memset(list.data, '\0', USERNAME_SIZE * LIST_SIZE);

  sync.lock();
  for(auto itr = onlineUser.lower_bound(first_user); itr != onlineUser.end(); itr++){
    std::string username = itr->first;

    if(index < offset){
      index++;
      continue;
    }

    if(index >= LIST_SIZE + offset || username > last_user)
      break;

    std::cout << username << " index: " << index << std::endl;
    for(size_t j = 0; j < username.size(); j++)
      list.data[index].data[j] = username[j];
    list.data[index].data[username.size()] = '\0';
    index++;
  }
  sync.unlock();

  return list;
}

bool ThreadHandler::isUserOnline(std::string name){

  sync.lock();
  bool isOnline = (onlineUser.find(name) != onlineUser.end());
  sync.unlock();

  return isOnline;
}

size_t ThreadHandler::getThreadByUser(std::string name){
  size_t response = 0;


  sync.lock();
  auto itr = onlineUser.find(name);
  if(itr == onlineUser.end())
    response = 0;
  else
    response = itr->second->id;
  sync.unlock();

  return response;
}

bool ThreadHandler::startChatting(threadData* thread1, size_t id){
  bool res = false;
  threadData * thread2;

  sync.lock();
  auto itr = threadTable.find(id);
  if(itr != threadTable.end()){
    thread2 = itr->second;

    if(thread1->state == ONLINE && thread2->state == ONLINE){
      thread1->state = CHATTING;
      thread2->state = WAITING;
      res = true;
    }
  }
  sync.unlock();

  return res;
}
