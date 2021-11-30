#include <iostream>
#include <stdio.h>
#include <net/messages.h>
#include <net/SocketWrapper.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <thread>
#include <mutex>
#include <vector>
#include <poll.h>
#include <sstream>
#include <dirent.h>
#include <termios.h>
#include <utils.h>

#define PASSWORD_LEN 45
#define BUFFER_LEN 65000

using namespace std;

/*
  CLIENT COMMAND:
    - !connect [server_ip] [server_port]
    - !get_online [page] [user_search]
    - !request [account_name]
    - !accept/refuse [account_name]
    - !logoff
*/

struct Data{
  EVP_PKEY *privateKey, *serverPublicKey, *CApublicKey;
  symkey_t CSkey, CCkey;
  X509* certificate;
  Crypto serverCrypto, clientCrypto;
  username_t user, contact;
  SocketWrapper sock;
  bool isChatting;
  byte* buffer;

  ~Data(){
    delete[] buffer;
    EVP_PKEY_free(privateKey);
    EVP_PKEY_free(serverPublicKey);
    EVP_PKEY_free(CApublicKey);
    X509_free(certificate);
    delete[] CSkey.data;
    delete[] CCkey.data;
  }

  Data(){
      CSkey.data = nullptr;
      CCkey.data = nullptr;
      privateKey = nullptr;
      serverPublicKey = nullptr;
      CApublicKey = nullptr;
      certificate = nullptr;
      isChatting = false;
      buffer = nullptr;
  }

};

/*
  Function to hide the echo to the terminal (used for password)
*/
void stdinEcho(bool enable = true){
    struct termios t;
    tcgetattr(STDIN_FILENO, &t);
    if( !enable )
        t.c_lflag &= ~ECHO;
    else
        t.c_lflag |= ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &t);
}

/*
  Funtion to split a string in a vector of strings
*/
vector<string> parseCommand(string buf, const char separator){
  vector<string> strings;
  istringstream stream(buf);
  string temp;

  while (getline(stream, temp, separator)) {
      strings.push_back(temp);
  }

  return strings;
}


void quitChatting(Data* data){
  data->isChatting = false;
  data->clientCrypto.cleanup();
  delete[] data->CCkey.data;
  data->CCkey.data = nullptr;
}

/*
  Function to initialize the data strucutre with the cipher the hash, load the
  CA certificate.
*/
bool init(Data* data){

  cout << "initialize..." << endl;

  data->isChatting = false;
  data->serverCrypto.setHash(EVP_sha256());
  data->serverCrypto.setCipher(EVP_aes_256_ctr());
  data->serverCrypto.transmitter();
  data->clientCrypto.setHash(data->serverCrypto.getHash());
  data->clientCrypto.setCipher(data->serverCrypto.getCipher());

  cout << "...Cipher and Hash function loaded" << endl;

  X509* certCA = data->serverCrypto.loadCertFromFile("certCA.pem");

  if(certCA == NULL){
    throw Exception(GENERIC, __LINE__, __FILE__, __func__);
  }

  data->CApublicKey = X509_get_pubkey(certCA);
  data->serverCrypto.addCert(certCA);

  cout << "...CA cartificate loaded" << endl;

  return true;
}

/*
  Function that start asking user input to logging in
*/
bool login(Data *data){
  string password, path, username;

  cout << "login: ";
  cin >> username;
  if(!cin || username.size() < 3 || username.size() > USERNAME_SIZE - 1){
    cout << "username not valid [size should be between 3 and 15]" << endl;
    return false;
  }

  memcpy(data->user.data, username.c_str(), username.size() + 1);

  cout << "password: ";

  stdinEcho(false);
  password.reserve(50);
  cin >> password;
  stdinEcho(true);

  if(!cin){
    cout << "something has gone wrong" << endl;
    return false;
  }

  cout << endl;

  std::cout << "private key path: ";
  std::cin >> path;

  if(!std::cin || path.size() > PATH_MAX){
    for(size_t i = 0; i < password.capacity(); i++){ password[i] = '\0'; }
    std::cout << "ERROR: password format non valid" << std::endl;
    return false;
  }

  data->privateKey = data->serverCrypto.loadPrvKeyFromFile(path.c_str(), password.c_str());

  for(size_t i = 0; i < password.capacity(); i++){ password[i] = '\0'; }

  if(data->privateKey == NULL){
    std::cout << "ERROR: failed to load the private key" << std::endl;
    return false;
  }

  std::cout << "... private key loaded " << std::endl;

  return true;
}

/*
  Function to connect to the server
*/
bool connectToServer(Data* data){
  struct sockaddr_in servaddr;
  std::string inBuf;
  std::cout << "*************** WELCOME " << data->user.data << " ***************\nTo start a new connection execute the command !connect\nTo exit execute the command !logoff" << std::endl;

  while(true){
    getline(cin, inBuf);

    if(!std::cin)
      continue;

    std::vector<std::string> commands = parseCommand(inBuf, ' ');

    if(commands.size() == 0)
      continue;


    if("!connect" == commands[0]){
      std::string serv_ip = "127.0.0.1", serv_port = "8080";

      if(commands.size() > 1)
        serv_ip = commands[1];

      if(commands.size() > 2)
        serv_port = commands[2];

      int port = 0;

      stringstream stream(serv_port);
      stream >> port;

      servaddr.sin_family = AF_INET;
      servaddr.sin_addr.s_addr = inet_addr(serv_ip.c_str());
      servaddr.sin_port = htons(port);

      cout << "connecting to server: " << serv_ip << ":" << port << endl;
      if( data->sock.Connect((struct sockaddr*)&servaddr, sizeof(servaddr)) == -1 ){
        cout << "ERROR: could not connect the socket to the server (errno = " << strerror(errno) << ")" << endl;
      }else{
        break;
      }
    }

    if("!logoff" == commands[0]){
      cout << "logging off...." << endl;
      return false;
    }

  }

  cout << "... server connected" << endl;

  return true;
}

/*
  function that authenticate the server
*/
bool authServer(Data* data){
  byte *buffer = new byte[BUFFER_LEN];
  memset(buffer, 0, BUFFER_LEN);

  size_t recvLen = 0;
  nonce_t serverNonce;
  Message* servMessage;

  std::cout << "starting server authentication..." << std::endl;

  //generate private ECDSA key
  EVP_PKEY* dh_key = data->serverCrypto.generateECDHKey(), *dh_pub;

  //generate client nonce
  nonce_t clientNonce;
  RAND_bytes((byte*)&clientNonce, sizeof(nonce_t));

  //prepare first message
  RcqCertMessage rcq = RcqCertMessage();
  rcq.setNonce(clientNonce);
  rcq.setDHKey(dh_key);

  rcq.Serialize(buffer, recvLen, BUFFER_LEN, &data->serverCrypto);
  data->serverCrypto.pushHistory(buffer, recvLen);

  // send the certificate request message
  data->sock.sendPacket(&rcq, buffer, recvLen, BUFFER_LEN, &data->serverCrypto);

  //retrieve the message from the server
  data->serverCrypto.setPubKey(data->CApublicKey);
  data->serverCrypto.setMode(PLAIN | SIGN);
  data->sock.recvPacket(buffer, recvLen, BUFFER_LEN, &data->serverCrypto);
  servMessage = Message::fromBuffer(buffer, recvLen, BUFFER_LEN, &data->serverCrypto);

  if(servMessage == nullptr || servMessage->getType() != SNDCERT){
    delete servMessage; delete[] buffer;
    std::cout << "ERROR: wrong message receive" << std::endl;
    return false;
  }

  SndCertMessage *snd = (SndCertMessage*)servMessage;

  //retrieve the cetification of the server the nonce of the server and his public ECDH key
  X509* certServ = snd->getCert();

  data->serverPublicKey = X509_get_pubkey(certServ);
  serverNonce = snd->getNonce();
  dh_pub = snd->getDHKey();

  data->serverCrypto.pushHistory(&serverNonce, sizeof(nonce_t));
  data->serverCrypto.setPubKey(data->serverPublicKey);

  X509_NAME* certName = X509_get_subject_name(certServ);
  char *certName_char = X509_NAME_oneline(certName, NULL, 0);
  std::cout << "server certificate: " << certName_char << std::endl;

  if( !data->serverCrypto.verifyCert(certServ) || strcmp(certName_char, "/C=IT/ST=Italy/L=Pisa/O=CyberCompany/CN=ChatServer.com")){
    delete snd; delete[] buffer; delete[] certName_char;
    std::cout << "ERROR: impossible to verify the server certificate" << std::endl; return false;
  }
  delete[] certName_char;

  if( !snd->Authenticate(buffer, recvLen, BUFFER_LEN, &data->serverCrypto) ){
    delete snd; delete[] buffer;
    std::cout << "ERROR: impossible to authenticate the server " << std::endl; return false;
  }

  //build the symmetric encryption key
  data->CSkey = data->serverCrypto.getEphemeralKey(dh_key, dh_pub);

  // cleaning some dishes
  delete snd;
  EVP_PKEY_free(dh_key);
  EVP_PKEY_free(dh_pub);

  //sending the ack to authenticate
  AckCertMessage ack;
  nonce_t ackNonce;

  RAND_bytes((byte*)&ackNonce, sizeof(nonce_t));

  ack.setNonce(ackNonce);
  ack.setUsername(data->user);

  // from now on the symmetric key for client-server ecryption will remain the same
  data->serverCrypto.setKey(data->CSkey);

  //using my private key to protect the ack message
  data->serverCrypto.setPrvKey(data->privateKey);
  data->serverCrypto.setMode(ENCRYPT | SIGN);
  data->sock.sendPacket(&ack, buffer, recvLen, BUFFER_LEN, &data->serverCrypto);
  data->serverCrypto.setPubKey(data->serverPublicKey);

  std::cout << "The server has been authenticated" << std::endl;

  delete[] buffer;
  return true;
}

/*
  function to handle info messages
*/
bool handleInfo(InfMesgMessage *mess, Data *data){
  InfoType inf = mess->getInfo();
  bool ret = false;
  size_t sendLen = 0;

  switch(inf){
    case LOGOFF:
      std::cout << "The session has been interrupted by the server" << std::endl;
      ret = true;
    break;
    case WRGKEY:
      std::cout << "The server has refused your connection." << std::endl;
      ret = true;
    break;
    case QUIT:
      quitChatting(data);
      cout << "**************** END CHAT " << data->contact.data << " *********************" << endl;
    break;
    case NOCLIENT:
      cout << "ERROR: there is no such client " << endl;
    break;
    case NORCQ:
      cout << "ERROR: this user has never requested to chat with you " << endl;
    break;
    case PING:
      data->sock.sendPacket(mess, data->buffer, sendLen, BUFFER_LEN, &data->serverCrypto);
      data->serverCrypto.updateIV();
    break;
    default:
      cout << "info message unrecognized" << endl;
    break;
  }

  return ret;
}

bool handleChat(SecMesgMessage *mess, Data *data){
  SecMesgMessage *wrapper = (SecMesgMessage*)mess;
  Message* inside;
  buffer_t recvData = wrapper->getData();
  size_t recvLen;

  //BUFFER_LEN > recvData.size always
  memcpy(data->buffer, recvData.data, recvData.size);
  recvLen = recvData.size;

  if(!Message::Authenticate(data->buffer, recvLen, BUFFER_LEN, &data->clientCrypto)){
    std::cout << "The following message is not authenticate by " << data->contact.data << " : ";
    return false;
  }

  inside = Message::fromBuffer(data->buffer, recvLen, BUFFER_LEN, &data->clientCrypto);

  if(inside != nullptr && inside->getType() == SECMESG){

    buffer_t printData = ((SecMesgMessage*)inside)->getData();

    data->clientCrypto.updateIV();

    //print the message
    std::cout << data->contact.data << "> ";
    for(size_t i = 0; i < printData.size; i++)
      std::cout << printData.data[i];
    std::cout << std::endl;

  }else{
    std::cout << "ERROR: the message cannot be parsed " << std::endl;
  }
  //cleaning
  delete inside;

  return false;
}


bool handleList(SndListMessage* lst, Data* data){
  usernamelist_t list = lst->getList();

  //print the online user list (every non-setted filed is equal to 0)
  cout << "******************** online users ************************\n";
  for(size_t i = 0; i < LIST_SIZE; i++){
    if(list.data[i].data[0] == '\0')
      break;
    cout << i << ") " << list.data[i].data << endl;
  }
  cout << "**********************************************************\n" << endl;
  cout << endl;

  return false;
}

bool handleRequest(RcqConnMessage* conn, Data* data){
  username_t user = conn->getUsername();

  //print the request
  std::cout << ">> request arrived from " << user.data << " (!accept/!refuse " << user.data << "?)<< " << std::endl;

  return false;
}

bool handleResponse(ResConnMessage *conn, Data *data){
  username_t tempUser;
  tempUser = conn->getUsername();

  memcpy(data->contact.data, tempUser.data, USERNAME_SIZE);

  if(conn->isAccepted())
    std::cout << ">> Request from " << data->contact.data << " accepted"<< std::endl;
  else
    std::cout << ">> Request from " << data->contact.data << " refused" << std::endl;

  return false;
}

EVP_PKEY* firstClient(AuthClnMessage* toSend, nonce_t nonce, Data* data){
  size_t sendLen, recvLen;
  Message *m;
  EVP_PKEY* dh_pub;
  SecMesgMessage wrapper;

  //send the wrapper and ciher for the server
  wrapper.setMessage(toSend, data->buffer, BUFFER_LEN, &data->clientCrypto);
  data->sock.sendPacket(&wrapper, data->buffer, sendLen, BUFFER_LEN, &data->serverCrypto);
  data->serverCrypto.updateIV();

  //wait for the response from the other client
  data->sock.recvPacket(data->buffer, recvLen, BUFFER_LEN, &data->serverCrypto);
  if(!Message::Authenticate(data->buffer, recvLen, BUFFER_LEN, &data->serverCrypto)){
    std::cout << "Impossible to authenticate the message" << std::endl;
    return NULL;
  }

  m = Message::fromBuffer(data->buffer, recvLen, BUFFER_LEN, &data->serverCrypto);
  data->serverCrypto.updateIV();
  if(m == nullptr || m->getType() != SECMESG){
    delete m;
    std::cout << "Impossible to Parse the message" << std::endl;
    return NULL;
  }

  buffer_t insideBuffer = ((SecMesgMessage*)m)->getData();

  //buffer size > insideBuffer.size always
  memcpy(data->buffer, insideBuffer.data, insideBuffer.size);

  size_t usedSize = insideBuffer.size;

  delete m;

  data->clientCrypto.pushHistory((byte*)&nonce, sizeof(nonce_t));
  if(!Message::Authenticate(data->buffer, usedSize, BUFFER_LEN, &data->clientCrypto)){
    std::cout << "Message from the client not signed" << std::endl;
    return NULL;
  }

  m = Message::fromBuffer(data->buffer, usedSize, BUFFER_LEN, &data->clientCrypto);
  if(m == NULL || m->getType() != AUTHCLN){
    delete m;
    return NULL;
  }

  nonce_t otherNonce = ((AuthClnMessage*)m)->getNonce();
  dh_pub = ((AuthClnMessage*)m)->getDHKey();
  data->clientCrypto.pushHistory((byte*)&otherNonce, sizeof(nonce_t));

  InfMesgMessage inf;
  SecMesgMessage wrp;
  inf.setInfo(DEFAULT);


  wrp.setMessage(&inf, data->buffer, BUFFER_LEN, &data->clientCrypto);
  data->sock.sendPacket(&wrp, data->buffer, sendLen, BUFFER_LEN, &data->serverCrypto);
  data->serverCrypto.updateIV();

  delete m;
  return dh_pub;
}

EVP_PKEY* secondClient(AuthClnMessage* toSend, nonce_t nonce, Data* data){
  size_t sendLen, recvLen;
  Message *m;
  EVP_PKEY* dh_pub;

  //wait for the response from the other client
  data->sock.recvPacket(data->buffer, recvLen, BUFFER_LEN, &data->serverCrypto);
  if(!Message::Authenticate(data->buffer, recvLen, BUFFER_LEN, &data->serverCrypto)){
    std::cout << "Impossible to authenticate the message.." << std::endl;
    return NULL;
  }

  m = Message::fromBuffer(data->buffer, recvLen, BUFFER_LEN, &data->serverCrypto);
  data->serverCrypto.updateIV();
  if(m == nullptr || m->getType() != SECMESG){
    std::cout << "Impossible to Authenticate the message.." << std::endl;
    return NULL;
  }

  buffer_t insideBuffer = ((SecMesgMessage*)m)->getData();

  //buffer size > insideBuffer.size always
  memcpy(data->buffer, insideBuffer.data, insideBuffer.size);

  size_t usedSize = insideBuffer.size;
  delete m;

  if(!Message::Authenticate(data->buffer, usedSize, BUFFER_LEN, &data->clientCrypto)){
    std::cout << "Message from the client not signed.." << std::endl;
    return NULL;
  }

  m = Message::fromBuffer(data->buffer, usedSize, BUFFER_LEN, &data->clientCrypto);
  if(m == nullptr || m->getType() != AUTHCLN){
    delete m;
    return NULL;
  }

  nonce_t otherNonce = ((AuthClnMessage*)m)->getNonce();
  dh_pub = ((AuthClnMessage*)m)->getDHKey();
  data->clientCrypto.pushHistory((byte*)&otherNonce, sizeof(nonce_t));

  delete m;

  //send the wrapper and ciher for the server
  SecMesgMessage wrapper;

  wrapper.setMessage(toSend, data->buffer, BUFFER_LEN, &data->clientCrypto);
  data->sock.sendPacket(&wrapper, data->buffer, sendLen, BUFFER_LEN, &data->serverCrypto);
  data->serverCrypto.updateIV();
  data->clientCrypto.pushHistory((byte*)&nonce, sizeof(nonce_t));

  InfMesgMessage inf;
  SecMesgMessage* wrp;

  data->sock.recvPacket(data->buffer, recvLen, BUFFER_LEN, &data->serverCrypto);
  if(!Message::Authenticate(data->buffer, recvLen, BUFFER_LEN, &data->serverCrypto)){
    cout << "error message from the other client not authenticated by the server" << endl;
    EVP_PKEY_free(dh_pub);
    return NULL;
  }

  m = Message::fromBuffer(data->buffer, recvLen, BUFFER_LEN, &data->serverCrypto);
  data->serverCrypto.updateIV();
  if(m == NULL || m->getType() != SECMESG){
    cout << "error message from the other client malformed" << endl;
    if(m != NULL) delete m;
    return NULL;
  }

  wrp = (SecMesgMessage*)m;
  buffer_t buffer = wrp->getData();

  memcpy(data->buffer, buffer.data, buffer.size);
  usedSize = buffer.size;
  delete m;

  if(!Message::Authenticate(data->buffer, usedSize, BUFFER_LEN, &data->clientCrypto)){
    cout << "error message from the other client not authenticated" << endl;
    return NULL;
  }

  return dh_pub;
}

bool handlePubK(SndPubkMessage *sndpubk, Data* data){
  bool isFirst;
  Message *m = nullptr;
  EVP_PKEY *publicClientKey, *dh_key, *dh_pub;
  size_t sendLen;
  SecMesgMessage messageWrapper;

  isFirst = sndpubk->isFirst();
  publicClientKey = sndpubk->getKey();

  AuthClnMessage auth;
  nonce_t selfNonce;

  RAND_bytes((byte*)&selfNonce, sizeof(nonce_t));
  dh_key = data->clientCrypto.generateECDHKey();


  //gnerate the ECDH private key and the nonce
  auth.setDHKey(dh_key);
  auth.setNonce(selfNonce);

  //sign the message with prvkey and wrap-it
  data->clientCrypto.setPrvKey(data->privateKey);
  data->clientCrypto.setPubKey(publicClientKey);
  data->clientCrypto.setMode(PLAIN | SIGN);
  auth.Serialize(data->buffer, sendLen, BUFFER_LEN, &data->clientCrypto);
  messageWrapper.setData(data->buffer, sendLen);


  if(isFirst){
    dh_pub = firstClient(&auth, selfNonce, data);
  }else{
    dh_pub = secondClient(&auth, selfNonce, data);
  }

  if(dh_pub == NULL){
    std::cout << "Impossible to complete the handshake with the other client" << std::endl;
    return false;
  }

  if(isFirst)
    data->clientCrypto.transmitter();
  else
    data->clientCrypto.receiver();

  data->CCkey = data->clientCrypto.getEphemeralKey(dh_key, dh_pub);

  //setting the symmetric key for client-client encryption
  data->clientCrypto.setKey(data->CCkey);
  data->clientCrypto.setMode(ENCRYPT | AUTH);
  data->isChatting = true;


  cout << "Succesful authentication, key generated." << endl;
  cout << "**************** CHAT WITH " << data->contact.data << " ********************" << endl;

  EVP_PKEY_free(dh_pub);
  EVP_PKEY_free(dh_key);

  if(m != nullptr)
    delete m;

  return false;
}

int mainLogic(){
  Data data;

  if( !init(&data) ){
    std::cout << "initalization goes wrong" << std::endl; return -1;
  }

  if( !login(&data) ){
    std::cout << "login goes wrong" << std::endl; return -1;
  }

  data.sock.init();

  if( !connectToServer(&data) )
    return 0;

  if( !authServer(&data) )
    return 0;

  data.serverCrypto.setMode(ENCRYPT | AUTH);

  // file descriptor array containing the socket and the stdin
  struct pollfd fds[2];

  fds[0].fd = 0;
  fds[0].events = POLLIN;
  fds[0].revents = 0;

  fds[1].fd = data.sock.getFd();
  fds[1].events = POLLIN;
  fds[1].revents = 0;

  //the client-client communication use the same crypto protocol as the client-server

  cout << "\n**************************************************************\n";
  cout << "The application is now fully working.\n";
  cout << "possible commands:\n";
  cout << "\t!logoff: exit from the program\n";
  cout << "\t!get_online: get the online users\n";
  cout << "\t!request [USER]: request a chat to [USER]\n";
  cout << "\t!accept/!refuse [USER]: accept or refuse a chat request\n coming from [USER]\n";
  cout << "**************************************************************\n";
  cout << endl;

  data.buffer = new byte[BUFFER_LEN];
  string inBuf;
  SecMesgMessage messageWrapper;
  size_t sendLen, recvLen;

  while(true){

    //start polling
    poll(fds, 2, -1);

    //data from the stdin
    if(fds[0].revents == POLLIN){
      fds[0].revents = 0;

      //reading the command
      getline(std::cin, inBuf);

      if(std::cin){

        //the logoff instruction works in every context
        if("!logoff" == inBuf){
          InfMesgMessage inf;
          inf.setInfo(LOGOFF);


          data.serverCrypto.startSend();
          data.serverCrypto.setPrvKey(data.privateKey);
          data.sock.sendPacket(&inf, data.buffer, sendLen, BUFFER_LEN, &data.serverCrypto);
          data.serverCrypto.updateIV();
          data.sock.Close();

          break;
        }

        //if the user is chatting then everything written is sent to the other client
        if(data.isChatting){
          if("!quit" == inBuf){
            InfMesgMessage inf;

            quitChatting(&data);

            inf.setInfo(QUIT);

            data.sock.sendPacket(&inf, data.buffer, sendLen, BUFFER_LEN, &data.serverCrypto);
            data.serverCrypto.updateIV();

            cout << "**************** END CHAT " << data.contact.data << " *********************" << endl;
          }else{

            SecMesgMessage chatMsg;

            //loading the data from the stdin to the ChatMsg message
            chatMsg.setData((byte*)inBuf.c_str(), strlen(inBuf.c_str()));

            //cipher the message using cryptoClient structure
            bool res = chatMsg.Serialize(data.buffer, sendLen, BUFFER_LEN, &data.clientCrypto);
            data.clientCrypto.updateIV();

            if(!res){
              std::cout << "error serializing the message" << std::endl;
              return -1;
            }

            //wrapping the message and cipher it using the crypto strucutre
            messageWrapper.setData(data.buffer, sendLen);

            data.sock.sendPacket(&messageWrapper, data.buffer, sendLen, BUFFER_LEN, &data.serverCrypto);
            data.serverCrypto.updateIV();
          }
        }else{
          Message *m = nullptr;

          vector<string> commands = parseCommand(inBuf, ' ');

          if("!get_online" == commands[0]){
            username_t username;
            memset(username.data, 0, sizeof(username));

            uint32_t offset = 0;
            if(commands.size() == 2){
              try{
                offset = std::stoi(commands[1]);
              }catch(...){
                if(commands[1].size() > USERNAME_SIZE - 1){
                  cout << "username to search too long or too short should be between 4 and 15" << endl;
                  continue;
                }
                memcpy(username.data, commands[1].c_str(), commands[1].size());
              }
            }

            if(commands.size() == 3){
              try{
                offset = std::stoi(commands[2]);
              }catch(...){
                cout << "impossible to parse: " << commands[2] << " into a number "<< endl;
                continue;
              }
            }

            m = new RcqListMessage();
            ((RcqListMessage*)m)->setOffset(offset);
            ((RcqListMessage*)m)->setUsername(username);

          }else if("!request" == commands[0] && commands.size() == 2){
            username_t username;

            memset(username.data, 0, USERNAME_SIZE);
            memcpy(username.data, commands[1].c_str(), commands[1].size());

            m = new RcqConnMessage();
            ((RcqConnMessage*)m)->setUsername(username);

          }else if(("!accept" == commands[0] || "!refuse" == commands[0]) && commands.size() == 2){

            memset(data.contact.data, 0, USERNAME_SIZE);
            memcpy(data.contact.data, commands[1].c_str(), commands[1].size());

            m = new ResConnMessage();

            ((ResConnMessage*)m)->setUsername(data.contact);
            if("!accept" == commands[0])
              ((ResConnMessage*)m)->accept();

          }else{
            cout << "Unrecognized command" << endl;
          }

          if(m != nullptr){
            data.sock.sendPacket(m, data.buffer, sendLen, BUFFER_LEN, &data.serverCrypto);
            data.serverCrypto.updateIV();
            delete m;
          }
        }
      }
    }

    //data from the server (socket)
    if(fds[1].revents == POLLIN){
      fds[1].revents = 0;

      if(!data.sock.recvPacket(data.buffer, recvLen, BUFFER_LEN, &data.serverCrypto)){
        data.sock.Close();
        break;
      }

      if(!Message::Authenticate(data.buffer, recvLen, BUFFER_LEN, &data.serverCrypto)){
        std::cout << "the current message is not authenticate by the server" << std::endl;
        continue;
      }

      Message *m = Message::fromBuffer(data.buffer, recvLen, BUFFER_LEN, &data.serverCrypto);

      if(m != nullptr){

        data.serverCrypto.updateIV();

        bool ret = false;
        // every informative message from the server is handled
        if(m->getType() == INFMESG){
          ret = handleInfo((InfMesgMessage*)m, &data);
        } else if(data.isChatting) { // if the user is chatting every non informative message is about the chat
          ret = handleChat((SecMesgMessage*)m, &data);
        }else{
          if(m->getType() == SNDLIST){
            ret = handleList((SndListMessage*)m, &data);
          }else if(m->getType() == RCQCONN){
            ret = handleRequest((RcqConnMessage*)m, &data);
          }else if(m->getType() == RESCONN){
            ret = handleResponse((ResConnMessage*)m, &data);
          }else if(m->getType() == SNDPUBK){
            ret = handlePubK((SndPubkMessage*)m, &data);
            data.clientCrypto.setMode(ENCRYPT | AUTH);
          }
        }

        delete m;

        if(ret){
          return 0;
        }
      }
    }

  }
  return 0;
}

int main(int argc, char* argv[]){
  int val;

  val = mainLogic();

  CRYPTO_cleanup_all_ex_data();

  return val;
}
