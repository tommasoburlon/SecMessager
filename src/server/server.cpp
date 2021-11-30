#include <net/messages.h>
#include <crypto/Crypto.h>
#include <net/SocketWrapper.h>
#include <server/MessageQueue.h>
#include <server/ThreadHandler.h>
#include <exception>
#include <limits.h>
#include <poll.h>
#include <unordered_set>
#include <utils.h>

#define TIMEOUT 1000
#define __DEBUG__ 0

/*
 function to handle kill signal
*/
jmp_buf jmpbuf;
void handler(int signum){
    longjmp(jmpbuf, 1);
}

bool threadAuth(threadData* data, byte *buffer, size_t size, username_t &clientServed){
  EVP_PKEY *defaultPubKey = data->crypto.getPubKey();
  Message* recvMess;
  size_t recvLen = 0, sendLen = 0;
  bool ret;

  //get the client initial session message
  ret = data->sock.recvPacket(buffer, recvLen, size, &data->crypto);
  recvMess = Message::fromBuffer(buffer, recvLen, size, &data->crypto);

  if(!ret || recvMess == NULL || recvMess->getType() != RCQCERT){
    delete recvMess;
    return false;
  }

  //decode the message and get all the data
  RcqCertMessage *rcq = (RcqCertMessage*)recvMess;
  SndCertMessage snd;
  nonce_t serverNonce;

  //get the client nonce and public ECDH
  data->dh_pub = rcq->getDHKey();
  data->crypto.pushHistory(buffer, recvLen);

  // generate private ECDH key
  data->dh_key = data->crypto.generateECDHKey();

  if(data->dh_key == NULL){ EVP_PKEY_free(data->dh_pub); return false;}

  //generate server nonce
  RAND_bytes((byte*)&serverNonce, sizeof(nonce_t));

  snd.setCert(data->cert);
  snd.setNonce(serverNonce);
  snd.setDHKey(data->dh_key);

  //send server data
  data->crypto.pushHistory(&serverNonce, sizeof(nonce_t));
  data->crypto.setMode(PLAIN | SIGN);
  data->sock.sendPacket(&snd, buffer, sendLen, size, &data->crypto);

  //generate the ephemeral key
   data->key = data->crypto.getEphemeralKey(data->dh_key, data->dh_pub);

  //some cleaning
  EVP_PKEY_free(data->dh_key);
  EVP_PKEY_free(data->dh_pub);
  data->dh_key = nullptr;
  data->dh_pub = nullptr;

  delete recvMess;

  //set the IV the symmetric key and some random EC public key
  data->crypto.setKey(data->key);
  data->crypto.setPubKey(defaultPubKey);

  data->crypto.setMode(ENCRYPT | SIGN);
  ret = data->sock.recvPacket(buffer, recvLen, size, &data->crypto);
  recvMess = Message::fromBuffer(buffer, recvLen, size, &data->crypto);

  if(!ret || recvMess == NULL || recvMess->getType() != ACKCERT){
    delete recvMess;
    return false;
  }

  AckCertMessage *ack = (AckCertMessage*)recvMess;
  EVP_PKEY* clientKey;
  username_t username = ack->getUsername();
  std::string username_str;

  memcpy(data->account.data, username.data, USERNAME_SIZE);
  username_str = data->account.data;

  //search for the user if i cannot find it maybe the DH protocol went wrong
  std::cout << username_str << std::endl;
  user_t *u = data->channel->getUserByName(username_str);
  if(u == nullptr){
    std::cout << "ERROR: Impossible to find the username, Abort" << std::endl;
    delete ack;
    return false;
  }

  //loading the clientServed structure
  memcpy(clientServed.data, username.data, USERNAME_SIZE);

  // getting the client pub key
  clientKey = u->publicKey;

  //insert the user in the online data structure
  if(!data->channel->setUserOnline(username_str, data)){
    std::cout << "ERROR: user already online" << std::endl;
    delete ack;
    return false;
  }

  data->crypto.setPubKey(clientKey);

  //authenticate the client
  if(!ack->Authenticate(buffer, recvLen, size, &data->crypto)){
    data->channel->setUserOffline(clientServed.data);
    std::cout << "Impossible to authenticate the client, Abort" << std::endl;
    delete ack;
    return false;
  }

  delete ack;
  return true;
}

void threadTask(threadData *data){
  // setting to null the future heap allocated data structure
  data->dh_key   = NULL;
  data->dh_pub   = NULL;
  data->key.data = NULL;

  data->state = INIT;
  data->crypto.setPrvKey(data->prvkey);

  // define the support buffer
  const size_t bufSize = 32000;
  byte* buffer = new byte[bufSize];
  size_t recvLen, sendLen;
  username_t clientServed;

  //try to authenticate the user
  bool isAuth = threadAuth(data, buffer, bufSize, clientServed);

  //if the authentication goes wrong end
  if(!isAuth){
    InfMesgMessage inf;
    inf.setInfo(WRGKEY);

    data->crypto.setMode(ENCRYPT | AUTH);
    data->sock.sendPacket(&inf, buffer, sendLen, bufSize, &data->crypto);

    data->state = ZOMBIE;
    std::cout << "ERROR: authentication goes wrong, Abort" << std::endl;

    data->sock.Close();
    delete[] buffer;
    data->channel->removeThread(data->id);

    return;
  }else{
    std::cout << "[thread_id = " << data->id << "]: client authenticated" << std::endl;
  }

  data->crypto.setMode(ENCRYPT | AUTH);
  size_t threadConnectedId = 0;
  data->state = ONLINE;

  // initialize a file descriptor for socket and one for the queue
  struct pollfd fds[2];

  fds[0].fd = data->mess.getFd();
  fds[0].events = POLLIN;
  fds[0].revents = 0;

  fds[1].fd = data->sock.getFd();
  fds[1].events = POLLIN;
  fds[1].revents = 0;

  //user that the client want to chat with
  std::unordered_set<std::string> rcqRecv, rcqSend;

  bool pingReceived = true;
  while(true){
    int ret = poll(fds, 2, TIMEOUT);

    if(ret == 0){
      if(!pingReceived)
        break;
      pingReceived = false;
      InfMesgMessage inf;
      inf.setInfo(PING);
      data->sock.sendPacket(&inf, buffer, sendLen, bufSize, &data->crypto);
      data->crypto.updateIV();
    }

    if(fds[0].revents == POLLIN){
      fds[0].revents = 0;

      Message *m = data->mess.front();
      data->mess.pop();

      // informative message have the priority
      if(m->getType() == INFMESG){
        InfMesgMessage *inf = (InfMesgMessage*)m;

        if(inf->getInfo() == QUIT){
          data->state = ONLINE;
          data->sock.sendPacket(inf, buffer, sendLen, bufSize, &data->crypto);
          data->crypto.updateIV();
        }

        delete inf;
      }else if(data->state == ONLINE || data->state == WAITING){
        if(m->getType() == RCQCONN){
          //insert the requested user
          rcqRecv.insert(std::string(((RcqConnMessage*)m)->getUsername().data));

          data->sock.sendPacket(m, buffer, sendLen, bufSize, &data->crypto);
          data->crypto.updateIV();

          delete m;
        }else if(m->getType() == RESCONN){

          username_t user;
          bool accepted;

          user = ((ResConnMessage*)m)->getUsername();
          accepted = ((ResConnMessage*)m)->isAccepted();

          data->sock.sendPacket(m, buffer, sendLen, bufSize, &data->crypto);
          data->crypto.updateIV();

          //search for the user to response
          if(!data->channel->isUserOnline(std::string(user.data)) || rcqSend.find(std::string(user.data)) == rcqSend.end()){
            std::cout << "ERROR: impossible to find the user" << std::endl;
            rcqSend.erase(std::string(user.data));
            rcqRecv.erase(std::string(user.data));
          }else if(accepted){
            // send the public key of the mate
            SndPubkMessage pubkmess;
            user_t *u = data->channel->getUserByName(std::string(user.data));

            pubkmess.setKey(u->publicKey);
            pubkmess.setFirst(false);

            data->sock.sendPacket(&pubkmess, buffer, recvLen, bufSize, &data->crypto);
            data->crypto.updateIV();

            threadConnectedId = data->channel->getThreadByUser(std::string(user.data));
            data->state = CHATTING;

            //rcqRecv.erase(std::string(user.data));
            for(auto itr : rcqRecv){
              ResConnMessage *inf = new ResConnMessage();
              inf->setUsername(clientServed);
              size_t idtmp = data->channel->getThreadByUser(itr);
              data->channel->sendMessageTo(inf, idtmp);
            }
            rcqRecv.clear();

            for(auto itr : rcqSend){
              ResConnMessage *inf = new ResConnMessage();
              inf->setUsername(clientServed);
              size_t idtmp = data->channel->getThreadByUser(itr);
              data->channel->sendMessageTo(inf, idtmp);
            }
            rcqSend.clear();
          }else{
            rcqSend.erase(std::string(user.data));
            rcqRecv.erase(std::string(user.data));
          }

          delete m;
        }
      }else if(data->state == CHATTING){
        // switching activity

        if(m->getType() == SECMESG){
          data->sock.sendPacket(m, buffer, sendLen, bufSize, &data->crypto);
          data->crypto.updateIV();
        }

        if(m->getType() == RCQCONN){
          ResConnMessage *inf = new ResConnMessage();
          inf->setUsername(clientServed);
          size_t idtmp = data->channel->getThreadByUser(((RcqConnMessage*)m)->getUsername().data);
          data->channel->sendMessageTo(inf, idtmp);
        }

        delete m;
      }
    }

    if(fds[1].revents == POLLIN){
      fds[1].revents = 0;

      Message *m;
      bool ret;

      data->crypto.startRecv();
      ret = data->sock.recvPacket(buffer, recvLen, bufSize, &data->crypto);

      if(!ret)
        break;

      if(!Message::Authenticate(buffer, recvLen, bufSize, &data->crypto)){
        std::cout << "impossible to authenticate the message" << std::endl;
        continue;
      }

      m = Message::fromBuffer(buffer, recvLen, bufSize, &data->crypto);

      if(m != nullptr){

        data->crypto.updateIV();

        // informative messages have got the priority
        if(m->getType() == INFMESG){
          InfMesgMessage *inf = (InfMesgMessage*)m;

          if(inf->getInfo() == LOGOFF){
            std::cout << "logging off: " << clientServed.data << std::endl;

            data->channel->setUserOffline(std::string(clientServed.data));
            inf->setInfo(QUIT);

            if(data->state == CHATTING && threadConnectedId > 0)
              data->channel->sendMessageTo(m, threadConnectedId);
            else
              delete m;

            data->state = ZOMBIE;
            break;
          }else if(inf->getInfo() == QUIT){
            inf->setInfo(QUIT);

            if(data->state == CHATTING && threadConnectedId > 0)
              data->channel->sendMessageTo(m, threadConnectedId);
            else
              delete m;
            data->state = ONLINE;
            threadConnectedId = 0;

          }else if(inf->getInfo() == PING){
            pingReceived = true;
            delete m;
          }else{
            delete m;
          }
        }else if(data->state == ONLINE){
          if(m->getType() == RCQCONN){
            username_t user;

            user   = ((RcqConnMessage*)m)->getUsername();
            std::cout << "new request to: " << user.data << std::endl;

            if(!data->channel->isUserOnline(std::string(user.data)) || !strcmp(user.data, clientServed.data)){
              std::cout << "impossible to request the data "<< std::endl;
              delete m;

              InfMesgMessage inf;
              inf.setInfo(NOCLIENT);
              data->sock.sendPacket(&inf, buffer, recvLen, bufSize, &data->crypto);
              data->crypto.updateIV();

            }else{
              size_t connThread = data->channel->getThreadByUser(std::string(user.data));
              std::cout << "request from: " << data->account.data << std::endl;
              ((RcqConnMessage*)m)->setUsername(data->account);

              std::cout << "thread_id: " << data->id << " -> " << connThread << std::endl;
              data->channel->sendMessageTo(m, connThread);

              rcqSend.insert(std::string(user.data));
            }
          }else if(m->getType() == RCQLIST){
            uint32_t offset;
            usernamelist_t list;
            username_t user;

            offset = ((RcqListMessage*)m)->getOffset();
            user   = ((RcqListMessage*)m)->getUsername();
            delete m;

            list = data->channel->getList(user, offset);

            m = new SndListMessage();
            ((SndListMessage*)m)->setList(list);

            data->crypto.startSend();
            data->sock.sendPacket(m, buffer, recvLen, bufSize, &data->crypto);
            data->crypto.updateIV();
            delete m;

          } else if(m->getType() == RESCONN){
            username_t user;
            bool accepted;

            user     = ((ResConnMessage*)m)->getUsername();
            accepted = ((ResConnMessage*)m)->isAccepted();


            if(!data->channel->isUserOnline(std::string(user.data)) || rcqRecv.find(std::string(user.data)) == rcqRecv.end()){
              std::cout << "the user " << std::string(user.data) << " has never requested a chat " << std::endl;
              delete m;

              InfMesgMessage inf;
              if(!data->channel->isUserOnline(std::string(user.data)))
                inf.setInfo(NOCLIENT);
              else
                inf.setInfo(NORCQ);
              data->sock.sendPacket(&inf, buffer, recvLen, bufSize, &data->crypto);
              data->crypto.updateIV();

            }else{
              size_t connThread = data->channel->getThreadByUser(std::string(user.data));
              ((ResConnMessage*)m)->setUsername(data->account);
              data->channel->sendMessageTo(m, connThread);

              rcqRecv.erase(std::string(user.data));

              if(accepted){
                bool ret = data->channel->startChatting(data, connThread);

                if(ret){
                  data->state = CHATTING;
                  threadConnectedId = connThread;

                  SndPubkMessage pubkmess;
                  user_t *u = data->channel->getUserByName(std::string(user.data));

                  pubkmess.setFirst(true);
                  pubkmess.setKey(u->publicKey);

                  data->sock.sendPacket(&pubkmess, buffer, recvLen, bufSize, &data->crypto);
                  data->crypto.updateIV();

                  for(auto itr : rcqRecv){
                    ResConnMessage *inf = new ResConnMessage();
                    inf->setUsername(clientServed);
                    size_t idtmp = data->channel->getThreadByUser(itr);
                    data->channel->sendMessageTo(inf, idtmp);
                  }
                  rcqRecv.clear();

                  for(auto itr : rcqSend){
                    ResConnMessage *inf = new ResConnMessage();
                    inf->setUsername(clientServed);
                    size_t idtmp = data->channel->getThreadByUser(itr);
                    data->channel->sendMessageTo(inf, idtmp);
                  }
                  rcqSend.clear();
                }
              }
            }
          }
        }else if(data->state == CHATTING){
          data->channel->sendMessageTo(m, threadConnectedId);
        }
      }

    }
  }

  InfMesgMessage inf;
  inf.setInfo(LOGOFF);
  data->sock.sendPacket(&inf, buffer, sendLen, bufSize, &data->crypto);
  data->crypto.updateIV();

  if(data->state == CHATTING){
    inf.setInfo(QUIT);
    data->channel->sendMessageTo(&inf, threadConnectedId);
  }

  data->channel->setUserOffline(clientServed.data);

  data->sock.Close();
  delete[] buffer;

  size_t threadId = data->id;
  std::cout << (data->channel->removeThread(data->id) ? "thread removed correctly" : "error while removing thread") <<  " [id = " << threadId << "]" << std::endl;

}

int main(int argc, char *argv[]){

  const char *portStr;

  ThreadHandler channel;

  portStr = argc < 2 ? "8080" : argv[1];

  Crypto c;
  EVP_PKEY *prvkey = c.loadPrvKeyFromFile("keyServer.pem"), *defaultPubKey;
  X509* cert = c.loadCertFromFile("certServer.pem");

  //load a standard public Elliptic Key
  defaultPubKey = c.loadPubKeyFromFile("ECpubkey.pem");

  //load the users keys
  channel.load("./pubkeys/", &c);

  //set cipher and hash methods
  c.setHash(EVP_sha256());
  c.setCipher(EVP_aes_256_ctr());

  unsigned int len;
  struct sockaddr_in servaddr, cli;
  SocketWrapper sock;
  sock.init();

  // assign ip and port to the socket
  int port = 0;
  sscanf(portStr, "%d", &port);

  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  servaddr.sin_port = htons(port);

  //bind the socket
  if( sock.Bind((struct sockaddr*)&servaddr, sizeof(servaddr)) == -1){
    std::cout << "ERROR: could not bind the socket (err = " << strerror(errno) << ")" << std::endl;
    goto end_server;
  }

  //start listening
  if( sock.Listen(5) == -1){
    std::cout << "ERROR: could not start the listen socket (err = " << strerror(errno) << ")" << std::endl;
    goto end_server;
  }

  std::cout << "start listening " << std::endl;

  if (setjmp(jmpbuf)) {
    return 0;
  }
  signal(SIGINT, handler);
  signal(SIGTERM, handler);

  while(true){

    // for every new socket

    memset(&cli, 0, sizeof(sockaddr_in));
    len = sizeof(sockaddr_in);
    SocketWrapper threadSock = sock.Accept((sockaddr*)&cli, &len);


    if(threadSock.getFd() < 0){
      std::cout << "impossible to accept new connection (err =  " << errno << "):" << strerror(errno) << std::endl;
    }else{
      threadData *data = new threadData;

      data->sock = threadSock;
      data->sock.settimeout(TIMEOUT);
      //create a new crypto object
      data->crypto = Crypto();
      data->crypto.setHash(c.getHash());
      data->crypto.setCipher(c.getCipher());
      data->crypto.setPubKey(defaultPubKey);
      data->crypto.setPrvKey(prvkey);
      data->crypto.receiver();

      data->channel = &channel;
      data->cert = cert;                // server certificate
      data->prvkey = prvkey;            // server private key
      data->th = std::thread(threadTask, data);
      data->th.detach(); // detaching the thread

      data->id = channel.insertNewThread(data);

      std::cout << "new thread  [threadId = " << data->id << "]" << std::endl;
    }
  }
end_server:
  EVP_PKEY_free(prvkey);
  EVP_PKEY_free(defaultPubKey);
  OPENSSL_free(cert);

  return 0;
}
