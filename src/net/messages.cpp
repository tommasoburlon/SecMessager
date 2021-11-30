#include <net/messages.h>

Message* Message::fromBuffer(byte* buf, size_t& size, size_t max, Crypto* crypto){
  MessageType type;
  msglen_t len;

  if(size < sizeof(msglen_t) + sizeof(MessageType))
    return nullptr;

  memcpy(&len, buf, sizeof(msglen_t));
  memcpy(&type, &buf[sizeof(msglen_t)], sizeof(MessageType));

  Message* m = nullptr;

  switch(type){
    case RCQCERT:
      m = new RcqCertMessage();
      break;
    case SNDCERT:
      m = new SndCertMessage();
      break;
    case ACKCERT:
      m = new AckCertMessage();
      break;
    case RCQLIST:
      m = new RcqListMessage();
      break;
    case SNDLIST:
      m = new SndListMessage();
      break;
    case RCQCONN:
      m = new RcqConnMessage();
      break;
    case RESCONN:
      m = new ResConnMessage();
      break;
    case SNDPUBK:
      m = new SndPubkMessage();
      break;
    case AUTHCLN:
      m = new AuthClnMessage();
      break;
    case SECMESG:
      m = new SecMesgMessage();
      break;
    case INFMESG:
      m = new InfMesgMessage();
      break;
    default:
      return nullptr;
  }

  bool ret = m->Deserialize(buf, size, max, crypto);

  if(!ret){
    delete m;
    return nullptr;
  }

  return m;
}

bool Message::Serialize(byte* buf, size_t &idx, size_t max, Crypto *crypto){
  size_t authSize, signSize, introSize, dataSize = 0, dataIdx, plainEnd, encryptEnd;

  bool isAuth, isSign, isEncrypt;

  isAuth    = crypto->getMode() & AUTH;
  isSign    = crypto->getMode() & SIGN;
  isEncrypt = crypto->getMode() & ENCRYPT;
  crypto->startSend();

  if((isAuth && crypto->getHash() == nullptr) || (isSign && crypto->getPrvKey() == nullptr)){
    std::cout << "ERROR: impossbile to authenticate/sign the message (hash or key undefined)" << std::endl;
    return false;
  }

  introSize = sizeof(msglen_t) + sizeof(MessageType);
  authSize = (isAuth ? crypto->getHashSize() : 0);
  signSize = (isSign ? crypto->getPrvKeySize() + 1 : 0);
  dataIdx = introSize + authSize + signSize;

  if(max < dataIdx){
    std::cout << "ERROR: serialize message buffer too small" << std::endl;
    return false;
  }

  // serialize the data field (virtual function)
  bool err = DataToBuffer(&buf[dataIdx], max - dataIdx, dataSize, crypto);
  MessageType type = this->getType();

  plainEnd = dataSize + dataIdx;
  encryptEnd = plainEnd;

  if(!err){
    std::cout << "Data serialization error" << std::endl;
    return false;
  }

  // preEncryptLen size of the messages before the encryption
  msglen_t preEncryptLen = authSize + signSize + dataSize;

  // len size of the message after the encryption
  msglen_t len = authSize + signSize +
    isEncrypt * crypto->getEncryptSize(dataSize) +
    (1 - isEncrypt) * dataSize;

  if(max < len + introSize + preEncryptLen){
    std::cout << "ERROR: serialize message buffer too small" << std::endl;
    return false;
  }

  // signa1ture build
  if(isSign){
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_PKEY* key = crypto->getPrvKey();
    unsigned int digestSize = crypto->getHashSize();
    iv_t iv = crypto->getIV();

    if(ctx == NULL){
      std::cout << "ERROR: impossible to create MD_CTX" << std::endl;
      return false;
    }

    #undef handle_error
    #define handle_error(x) if((x) != 1){ std::cout << "ERROR: impossible to sign" << std::endl; crypto->loadOldPRAND(); EVP_MD_CTX_free(ctx); return false; }

    // loading the constant-PRNG is mandatory for ECDSA
    crypto->loadFakePRAND();

    handle_error( EVP_SignInit(ctx, crypto->getHash()) );

    handle_error( EVP_SignUpdate(ctx, &buf[dataIdx], dataSize) );

    handle_error( EVP_SignUpdate(ctx, &preEncryptLen, sizeof(msglen_t)) );

    handle_error( EVP_SignUpdate(ctx, &type, sizeof(MessageType)) );

    handle_error( EVP_SignUpdate(ctx, crypto->getHistoryDigest(), crypto->getHashSize()) );

    if(iv.data != nullptr)
      handle_error( EVP_SignUpdate(ctx, iv.data, iv.size) );

    handle_error( EVP_SignFinal(ctx, &buf[introSize], &digestSize, key) );

    EVP_MD_CTX_free(ctx);

    crypto->loadOldPRAND();

    for(byte i = 1; i <= signSize - digestSize; i++)
      memcpy(&buf[introSize + signSize - i], &i, sizeof(byte));

  }

  // Encryption using symmetric key
  if(isEncrypt){

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    iv_t iv = crypto->getIV();
    symkey_t key = crypto->getKey();
    int update_len = 0;

    if(key.size < (unsigned int)EVP_CIPHER_key_length(crypto->getCipher())){
      std::cout << "ERROR: symmetric key too small " << std::endl;
      return false;
    }

    if(ctx == NULL){
      std::cout << "ERROR: impossible to create CIPHER_CTX" << std::endl;
      return false;
    }

    #undef handle_error
    #define handle_error(x) if((x) != 1){ std::cout << "ERROR: impossible to encrypt " << std::endl; EVP_CIPHER_CTX_free(ctx); return false; }

    memset(&buf[encryptEnd], 0, len - authSize - signSize);

    handle_error( EVP_EncryptInit_ex(ctx, crypto->getCipher(), NULL, key.data, iv.data) );

    handle_error( EVP_EncryptUpdate(ctx, &buf[encryptEnd], &update_len, &buf[dataIdx], dataSize) );
    encryptEnd += update_len;

    handle_error(  EVP_EncryptFinal(ctx, &buf[encryptEnd], &update_len) );
    encryptEnd += update_len;

    EVP_CIPHER_CTX_free(ctx);

    memmove(&buf[dataIdx], &buf[plainEnd], (encryptEnd - plainEnd));

    if(len < encryptEnd - plainEnd + authSize + signSize){
      std::cout << "data dimension problem.. " << len << " vs " << encryptEnd + authSize + signSize - plainEnd << std::endl;
      return false;
    }
  }

  //Auth field build
  if(isAuth){
    HMAC_CTX* ctx = HMAC_CTX_new();
    symkey_t key = crypto->getKey();
    unsigned int outlen;
    iv_t iv = crypto->getIV();

    if(ctx == NULL){
      std::cout << "ERROR: impossible to create HMAC ctx " << std::endl;
      return false;
    }

    #undef handle_error
    #define handle_error(x) if((x) != 1){ std::cout << "ERROR: impossible to auth" << std::endl; HMAC_CTX_free(ctx); return false; }

    handle_error( HMAC_Init_ex(ctx, key.data, key.size, crypto->getHash(), NULL) );

    handle_error( HMAC_Update(ctx, &buf[dataIdx], len - authSize - signSize) );

    handle_error( HMAC_Update(ctx, (const unsigned char*)&len, sizeof(msglen_t)) );

    handle_error( HMAC_Update(ctx, (const unsigned char*)&type, sizeof(MessageType)) );

    handle_error( HMAC_Update(ctx, crypto->getHistoryDigest(), crypto->getHashSize()) );

    if(iv.data != nullptr)
      handle_error( HMAC_Update(ctx, iv.data, iv.size) );

    handle_error( HMAC_Final(ctx, &buf[introSize + signSize], &outlen) );

    HMAC_CTX_free(ctx);

  }

  // total size of the message
  idx = len + introSize;

  // copy the prelude of the message
  len = htons(len);
  memcpy(buf, &len, sizeof(msglen_t));
  memcpy(&buf[sizeof(msglen_t)], &type, sizeof(MessageType));

  return true;
};

bool Message::Decrypt(byte *buf, size_t &finalSize, size_t maxSize, Crypto *crypto){

  size_t authSize, signSize, decryptIdx, preludeSize;
  msglen_t len;
  bool isAuth, isSign, isEncrypt;

  isAuth    = crypto->getMode() & AUTH;
  isSign    = crypto->getMode() & SIGN;
  isEncrypt = crypto->getMode() & ENCRYPT;
  crypto->startRecv();

  if(finalSize < sizeof(msglen_t)){
    std::cout << "ERROR: Decrypt buffer size too short" << std::endl;
    return false;
  }

  if((isAuth && crypto->getHash() == nullptr) || (isSign && crypto->getPubKey() == nullptr)){
    std::cout << "ERROR: impossbile to authenticate/sign the message (hash or key undefined)" << std::endl;
    return false;
  }

  memcpy(&len, buf, sizeof(msglen_t));
  len = ntohs(len);

  preludeSize = sizeof(msglen_t) + sizeof(MessageType);
  signSize = (isSign ? crypto->getPubKeySize() + 1 : 0);
  authSize = (isAuth ? crypto->getHashSize() : 0);
  decryptIdx = preludeSize + signSize + authSize;

  if(preludeSize + len > finalSize || preludeSize + 2 * len > maxSize){
    std::cout << "ERROR: Decrypt buffer size too short size " << std::endl;
    return false;
  }

  if(isEncrypt){

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    symkey_t key = crypto->getKey();
    iv_t iv = crypto->getIV();
    int update_len = 0, encrypt_len = 0;

    if(ctx == NULL){
      std::cout << "ERROR: impossible to create CIPHER_CTX" << std::endl;
      return false;
    }

    #undef handle_error
    #define handle_error(x) if((x) != 1){ std::cout << "ERROR: impossible to decrypt" << std::endl; EVP_CIPHER_CTX_free(ctx); return false; }

    handle_error( EVP_DecryptInit(ctx, crypto->getCipher(), key.data, iv.data) );

    handle_error( EVP_DecryptUpdate(ctx, &buf[finalSize], &update_len, &buf[decryptIdx], finalSize - decryptIdx) );
    encrypt_len += update_len;

    handle_error( EVP_DecryptFinal(ctx, &buf[finalSize + update_len], &update_len) );
    encrypt_len += update_len;

    EVP_CIPHER_CTX_free(ctx);

    memmove(&buf[decryptIdx], &buf[finalSize], encrypt_len);


    finalSize = encrypt_len + signSize + authSize + preludeSize;
    len = (finalSize - preludeSize);

    len = htons(len);
    memcpy(buf, &len, sizeof(msglen_t));
  }

  return true;
}

bool Message::Authenticate(byte *buf, size_t size, size_t maxSize, Crypto *crypto){
  size_t authSize, signSize, dataSize, decryptIdx, preludeSize;
  msglen_t len;
  MessageType type;
  iv_t iv = crypto->getIV();
  bool isAuth, isSign;

  isAuth    = crypto->getMode() & AUTH;
  isSign    = crypto->getMode() & SIGN;
  crypto->startRecv();

  if((isAuth && crypto->getHash() == nullptr) || (isSign && crypto->getPubKey() == nullptr)){
    std::cout << "ERROR: impossbile to authenticate/sign the message (hash or key undefined)" << std::endl;
    return false;
  }

  if(size < sizeof(msglen_t) + sizeof(MessageType)){
    std::cout << "ERROR: Auth buffer size too short" << std::endl;
    return false;
  }

  memcpy(&len, buf, sizeof(msglen_t));
  len = ntohs(len);

  memcpy(&type, &buf[sizeof(msglen_t)], sizeof(MessageType));

  preludeSize = sizeof(msglen_t) + sizeof(MessageType);
  signSize = (isSign ? crypto->getPubKeySize() + 1 : 0);
  authSize = (isAuth ? crypto->getHashSize() : 0);
  decryptIdx = preludeSize + signSize + authSize;
  dataSize = len - signSize - authSize;

  if(preludeSize + len > size || preludeSize + 2 * len > maxSize){
    std::cout << "ERROR: Auth buffer size too short" << std::endl;
    return false;
  }

  if(isSign){
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    int rc;
    byte padding = 0;
    EVP_PKEY* key = crypto->getPubKey();
    size_t signIdx = preludeSize, trueSignSize;

    //extract the padding to calculate the size of the signature
    for(byte i = 1; i < signSize; i++){
      memcpy(&padding, &buf[signIdx + signSize - i], sizeof(byte));
      if(padding != i){
        padding = i - 1;
        break;
      }
    }

    if(ctx == NULL){
      std::cout << "ERROR: impossible to create MD_CTX" << std::endl;
      return false;
    }

    #undef handle_error
    #define handle_error(x) if((x) != 1){ std::cout << "ERROR: impossible to verify" << std::endl; crypto->loadOldPRAND(); EVP_MD_CTX_free(ctx); return false; }

    trueSignSize = signSize - padding;

    crypto->loadFakePRAND();

    handle_error( EVP_VerifyInit(ctx, crypto->getHash()) );

    handle_error( EVP_VerifyUpdate(ctx, &buf[decryptIdx], dataSize) );

    handle_error( EVP_VerifyUpdate(ctx, &len, sizeof(msglen_t)) );

    handle_error( EVP_VerifyUpdate(ctx, &type, sizeof(MessageType)) );

    handle_error( EVP_VerifyUpdate(ctx, crypto->getHistoryDigest(), crypto->getHashSize()) );

    if(iv.data != nullptr)
      handle_error( EVP_VerifyUpdate(ctx, iv.data, iv.size) );

    rc = EVP_VerifyFinal(ctx, &buf[signIdx], trueSignSize, key);

    EVP_MD_CTX_free(ctx);

    crypto->loadOldPRAND();

    if(rc != 1){
      return false;
    }
  }

  if(isAuth){
    HMAC_CTX* ctx = HMAC_CTX_new();
    symkey_t key = crypto->getKey();
    unsigned int outlen;
    size_t authIdx = preludeSize + signSize;
    iv_t iv = crypto->getIV();

    if(ctx == NULL){
      std::cout << "ERROR: impossible to create HMAC_CTX" << std::endl;
      return false;
    }

    #undef handle_error
    #define handle_error(x) if((x) != 1){ std::cout << "ERROR: impossible to auth" << std::endl; HMAC_CTX_free(ctx); return false; }


    handle_error( HMAC_Init_ex(ctx, key.data, key.size, crypto->getHash(), NULL) );

    handle_error( HMAC_Update(ctx, &buf[decryptIdx], dataSize) );

    handle_error( HMAC_Update(ctx, (const unsigned char*)&len, sizeof(msglen_t)) );

    handle_error( HMAC_Update(ctx, (const unsigned char*)&type, sizeof(MessageType)) );

    handle_error( HMAC_Update(ctx, crypto->getHistoryDigest(), crypto->getHashSize()) );

    if(iv.data != nullptr)
      handle_error( HMAC_Update(ctx, iv.data, iv.size) );

    handle_error( HMAC_Final(ctx, &buf[decryptIdx + dataSize], &outlen) );


    HMAC_CTX_free(ctx);

    if(CRYPTO_memcmp(&buf[decryptIdx + dataSize], &buf[authIdx], crypto->getHashSize()) != 0){
      return false;
    }
  }
  return true;
}

bool Message::Deserialize(byte* buf, size_t &finalSize, size_t maxSize, Crypto *crypto){
  msglen_t len;
  MessageType type;
  size_t preludeSize, signSize, authSize, decryptIdx;
  bool isAuth, isSign;

  isAuth    = crypto->getMode() & AUTH;
  isSign    = crypto->getMode() & SIGN;
  crypto->startRecv();

  if((isAuth && crypto->getHash() == nullptr) || (isSign && crypto->getPubKey() == nullptr)){
    std::cout << "ERROR: impossbile to authenticate/sign the message (hash or key undefined)" << std::endl;
    return false;
  }

  if(maxSize < sizeof(msglen_t) + sizeof(MessageType)){
    std::cout << "ERROR: Deserialize buffer too small " << std::endl;
    return false;
  }

  //load the type and the length of the data field
  memcpy(&len, buf, sizeof(msglen_t));
  len = ntohs(len);

  memcpy(&type, &buf[sizeof(msglen_t)], sizeof(MessageType));

  preludeSize = sizeof(msglen_t) + sizeof(MessageType);
  signSize = (isSign ? crypto->getPubKeySize() + 1 : 0);
  authSize = (isAuth ? crypto->getHashSize() : 0);
  decryptIdx = preludeSize + signSize + authSize;

  if(maxSize < 2 * len + preludeSize){
    std::cout << "ERROR: Deserialize buffer too small " << std::endl;
    return false;
  }

  if(type != getType())
    return false;

  bool ret = Decrypt(buf, finalSize, maxSize, crypto);

  if(!ret)
    return false;

  size_t tempSize;
  ret = BufferToData(&buf[decryptIdx], (finalSize - decryptIdx), tempSize, crypto);

  return ret;
};

// function to serialize X509 certificate
template <class T = X509*> size_t SerializeSingleData(byte* buf, size_t maxSize, bool &err, Crypto *c, X509* obj){
  msglen_t size = 0;

  byte *ptr = &buf[sizeof(msglen_t)];
  size = i2d_X509(obj, NULL);

  if(maxSize < size + sizeof(size)){
    err = true;
    return 0;
  }

  size = htons(i2d_X509(obj, &ptr));
  //insert the size of the certificate (should be below 65000bytes)
  memcpy(buf, &size, sizeof(msglen_t));

  err = false;

  return ntohs(size) + sizeof(msglen_t);
}

//function to serialize EVP_PKEY
template <class T = dh_key_t> size_t SerializeSingleData(byte* buf, size_t maxSize, bool &err, Crypto *c, dh_key_t obj){
  msglen_t keylen;

  byte *ptr = &buf[sizeof(msglen_t)];
  keylen = i2d_PublicKey(obj.data, NULL);

  if(maxSize < keylen + sizeof(keylen)){
    err = true;
    return 0;
  }

  keylen = htons(i2d_PublicKey(obj.data, &ptr));
  memcpy(buf, &keylen, sizeof(msglen_t));

  return ntohs(keylen) + sizeof(msglen_t);
}

template <class T = ec_key_t> size_t SerializeSingleData(byte* buf, size_t maxSize, bool &err, Crypto *c, ec_key_t obj){
  msglen_t keylen;

  byte *ptr = &buf[sizeof(msglen_t)];
  keylen = i2d_PublicKey(obj.data, NULL);


  if(maxSize < keylen + sizeof(keylen)){
    err = true;
    return 0;
  }

  keylen = htons(i2d_PublicKey(obj.data, &ptr));
  memcpy(buf, &keylen, sizeof(msglen_t));

  return ntohs(keylen) + sizeof(msglen_t);
}

//function to serialize EVP_PKEY
template <class T = buffer_t> size_t SerializeSingleData(byte* buf, size_t maxSize, bool &err, Crypto *c, buffer_t obj){
  if(maxSize < sizeof(msglen_t) + obj.size){
    std::cout << "ERROR: Serialize buffer_t, buffer too small" << std::endl;
    err = true;
    return 0;
  }

  msglen_t size = htons(obj.size);
  memcpy(buf, &size, sizeof(msglen_t));

  memcpy(&buf[sizeof(msglen_t)], obj.data, obj.size);

  return obj.size + sizeof(msglen_t);
}

// template function to serialize a linear data structure T
template <class T> size_t SerializeLinearData(byte* buf, size_t maxSize, bool &err, Crypto *c, T obj){
  if(maxSize < sizeof(T)){
    err = true;
    return 0;
  }
  memcpy(buf, &obj, sizeof(T));

  return sizeof(T);
}

template <class T = username_t> size_t SerializeSingleData(byte* buf, size_t maxSize, bool &err, Crypto *c, username_t obj){
  return SerializeLinearData(buf, maxSize, err, c, obj);
}

template <class T = bool> size_t SerializeSingleData(byte* buf, size_t maxSize, bool &err, Crypto *c, bool obj){
  return SerializeLinearData(buf, maxSize, err, c, obj);
}

template <class T = uint32_t> size_t SerializeSingleData(byte* buf, size_t maxSize, bool &err, Crypto *c, uint32_t obj){
  return SerializeLinearData(buf, maxSize, err, c, htonl(obj));
}

template <class T = usernamelist_t> size_t SerializeSingleData(byte* buf, size_t maxSize, bool &err, Crypto *c, usernamelist_t obj){
  return SerializeLinearData(buf, maxSize, err, c, obj);
}

template <class T = InfoType> size_t SerializeSingleData(byte* buf, size_t maxSize, bool &err, Crypto *c, InfoType obj){
  return SerializeLinearData(buf, maxSize, err, c, obj);
}

// nonce_t is linear
template <class T = nonce_t> size_t SerializeSingleData(byte* buf, size_t maxSize, bool &err, Crypto *c, nonce_t obj){
  return SerializeLinearData(buf, maxSize, err, c, obj);
}

// functions to permit recursive template definition
template<typename ...ArgsType> size_t SerializeData(byte* buf, size_t maxSize, bool &err, Crypto *c, ArgsType... args);

template <> size_t SerializeData(byte* buf, size_t maxSize, bool &err, Crypto *c){
  return 0;
}

template <class T, class ...ArgsType> size_t SerializeData(byte* buf, size_t maxSize, bool &err, Crypto *c, T obj, ArgsType... args){
  size_t idx = 0;

  idx += SerializeSingleData(buf, maxSize, err, c, obj);
  if(err) return 0;
  idx += SerializeData(&buf[idx], maxSize - idx, err, c, args...);
  if(err) return 0;
  return idx;
}


template <class T = X509**> size_t DeserializeSingleData(const byte* buf, size_t maxSize, bool &err, Crypto *c, X509** obj){
  const byte *subbuf = nullptr;
  const byte **ptr;
  msglen_t size = 0;

  if(maxSize < sizeof(msglen_t)){
    err = true;
    return 0;
  }

  memcpy(&size, buf, sizeof(msglen_t));
  size = ntohs(size);

  if(maxSize < sizeof(msglen_t) + size){
    err = true;
    return 0;
  }

  subbuf = &buf[sizeof(msglen_t)];
  ptr = &subbuf;

  (*obj) = d2i_X509(NULL, ptr, size);
  err = (*obj) == NULL;
  return size + sizeof(msglen_t);
}

template <class T = dh_key_t> size_t DeserializeSingleData(const byte* buf, size_t maxSize, bool &err, Crypto *c, dh_key_t* obj){
  msglen_t keylen;
  const byte* ptr = &buf[sizeof(msglen_t)];

  if(maxSize < sizeof(msglen_t)){
    err = true;
    return 0;
  }

  memcpy(&keylen, buf, sizeof(msglen_t));
  keylen = ntohs(keylen);

  if(maxSize < sizeof(msglen_t) + keylen){
    err = true;
    return 0;
  }

  obj->data = Crypto::generateECDHKey();
  if(NULL == d2i_PublicKey(EVP_PKEY_EC, &obj->data, &ptr, keylen)){
    std::cout << "ERROR tryng to decode DH key" << std::endl;
    err = true;
    return 0;
  }

  return keylen + sizeof(msglen_t);
}

template <class T = ec_key_t> size_t DeserializeSingleData(const byte* buf, size_t maxSize, bool &err, Crypto *c, ec_key_t* obj){
  msglen_t keylen;
  const byte* ptr = &buf[sizeof(msglen_t)];

  if(maxSize < sizeof(msglen_t)){
    err = true;
    return 0;
  }

  memcpy(&keylen, buf, sizeof(msglen_t));
  keylen = ntohs(keylen);

  if(maxSize < sizeof(msglen_t) + keylen){
    err = true;
    return 0;
  }

  obj->data = c->getPrvKey();
  if(NULL == d2i_PublicKey(EVP_PKEY_EC, &obj->data, &ptr, keylen)){
    std::cout << "ERROR tryng to decode EC key" << std::endl;
    err = true;
    return 0;
  }

  return keylen + sizeof(msglen_t);
}

template <class T = buffer_t> size_t DeserializeSingleData(byte* buf, size_t maxSize, bool &err, Crypto *c, buffer_t *obj){

  if(maxSize < sizeof(msglen_t)){
    std::cout << "ERROR: Deserialize buffer_t len, buffer too small" << std::endl;
    err = true;
    return 0;
  }

  memcpy(&obj->size, buf, sizeof(msglen_t));
  obj->size = ntohs(obj->size);

  if(maxSize < obj->size + sizeof(msglen_t)){
    std::cout << "ERROR: Deserialize buffer_t data, buffer too small" << maxSize << "vs." << obj->size + sizeof(msglen_t) << std::endl;
    err = true;
    return 0;
  }

  obj->data = new byte[obj->size];
  memcpy(obj->data, &buf[sizeof(msglen_t)], obj->size);

  return obj->size + sizeof(msglen_t);
}

template <class T> size_t DeserializeLinearData(byte* buf, size_t maxSize, bool &err, Crypto *c, T* obj){
  if(maxSize < sizeof(T)){
    err = true;
    return 0;
  }

  memcpy(obj, buf, sizeof(T));

  err = false;
  return sizeof(T);
}

template <class T = username_t> size_t DeserializeSingleData(byte* buf, size_t maxSize, bool &err, Crypto *c, username_t* obj){
  if(maxSize < USERNAME_SIZE){
    err = true;
    return 0;
  }

  memcpy(obj->data, buf, USERNAME_SIZE);

  err = false;
  return USERNAME_SIZE;
}

template <class T = bool> size_t DeserializeSingleData(byte* buf, size_t maxSize, bool &err, Crypto *c, bool* obj){
  return DeserializeLinearData(buf, maxSize, err, c, obj);
}

template <class T = usernamelist_t> size_t DeserializeSingleData(byte* buf, size_t maxSize, bool &err, Crypto *c, usernamelist_t* obj){
  if(maxSize < USERNAME_SIZE * LIST_SIZE){
    err = true;
    return 0;
  }

  memcpy(obj->data, buf, USERNAME_SIZE * LIST_SIZE);

  err = false;
  return USERNAME_SIZE * LIST_SIZE;
}

template <class T = InfoType> size_t DeserializeSingleData(byte* buf, size_t maxSize, bool &err, Crypto *c, InfoType* obj){
  return DeserializeLinearData(buf, maxSize, err, c, obj);
}

template <class T = uint32_t> size_t DeserializeSingleData(byte* buf, size_t maxSize, bool &err, Crypto *c, uint32_t* obj){
  size_t ret = DeserializeLinearData(buf, maxSize, err, c, obj);
  (*obj) = ntohl((*obj));
  return ret;
}

template <class T = nonce_t> size_t DeserializeSingleData(byte* buf, size_t maxSize, bool &err, Crypto *c, nonce_t* obj){
  return DeserializeLinearData(buf, maxSize, err, c, obj);
}


template <class ...ArgsType> size_t DeserializeData(byte* buf, size_t maxSize, bool &err, Crypto *c, ArgsType*... args);

template <> size_t DeserializeData(byte* buf, size_t maxSize, bool &err, Crypto *c){ return 0; };

template <class T, class ...ArgsType> size_t DeserializeData(byte* buf, size_t maxSize, bool &err, Crypto *c, T* obj, ArgsType*... args){
  size_t idx = 0;
  idx += DeserializeSingleData<T>(buf, maxSize, err, c, obj);
  if(err) return 0;
  idx += DeserializeData(&buf[idx], maxSize - idx, err, c, args...);
  if(err) return 0;
  return idx;
};


// messages serialize/deserialize methods
bool RcqCertMessage::DataToBuffer(byte *buf, size_t max, size_t &finalSize, Crypto *c){
  bool err = false;
  finalSize = SerializeData(buf, max, err, c, dh_public, nonce);
  return !err;
}

bool RcqCertMessage::BufferToData(byte *buf, size_t max, size_t &finalSize, Crypto *c){
  bool err = false;
  finalSize = DeserializeData(buf, max, err, c, &dh_public, &nonce);
  return !err;
}

bool SndCertMessage::DataToBuffer(byte *buf, size_t max, size_t &finalSize, Crypto *c){
  bool err = false;
  finalSize = SerializeData(buf, max, err, c, cert, dh_public, nonce);
  return !err;
}

bool SndCertMessage::BufferToData(byte *buf, size_t max, size_t &finalSize, Crypto *c){
  bool err = false;
  finalSize = DeserializeData(buf, max, err, c, &cert, &dh_public, &nonce);
  return !err;
}

bool AckCertMessage::DataToBuffer(byte *buf, size_t max, size_t &finalSize, Crypto *c){
  bool err = false;
  finalSize = SerializeData(buf, max, err, c, user, nonce);
  return !err;
}

bool AckCertMessage::BufferToData(byte *buf, size_t max, size_t &finalSize, Crypto *c){
  bool err = false;
  finalSize = DeserializeData(buf, max, err, c, &user, &nonce);
  return !err;
}

bool RcqListMessage::DataToBuffer(byte *buf, size_t max, size_t &finalSize, Crypto *c){
  bool err = false;
  finalSize = SerializeData(buf, max, err, c, user, offset);
  return !err;
}

bool RcqListMessage::BufferToData(byte *buf, size_t max, size_t &finalSize, Crypto *c){
  bool err = false;
  finalSize = DeserializeData(buf, max, err, c, &user, &offset);
  return !err;
}

bool SndListMessage::DataToBuffer(byte *buf, size_t max, size_t &finalSize, Crypto *c){
  bool err = false;
  finalSize = SerializeData(buf, max, err, c, list);
  return !err;
}

bool SndListMessage::BufferToData(byte *buf, size_t max, size_t &finalSize, Crypto *c){
  bool err = false;
  finalSize = DeserializeData(buf, max, err, c, &list);
  return !err;
}

bool RcqConnMessage::DataToBuffer(byte *buf, size_t max, size_t &finalSize, Crypto *c){
  bool err = false;
  finalSize = SerializeData(buf, max, err, c, user);
  return !err;
}

bool RcqConnMessage::BufferToData(byte *buf, size_t max, size_t &finalSize, Crypto *c){
  bool err = false;
  finalSize = DeserializeData(buf, max, err, c, &user);
  return !err;
}

bool ResConnMessage::DataToBuffer(byte *buf, size_t max, size_t &finalSize, Crypto *c){
  bool err = false;
  finalSize = SerializeData(buf, max, err, c, user, accepted);
  return !err;
}

bool ResConnMessage::BufferToData(byte *buf, size_t max, size_t &finalSize, Crypto *c){
  bool err = false;
  finalSize = DeserializeData(buf, max, err, c, &user, &accepted);
  return !err;
}

bool SndPubkMessage::DataToBuffer(byte *buf, size_t max, size_t &finalSize, Crypto *c){
  bool err = false;
  finalSize = SerializeData(buf, max, err, c, pubkey, first);
  return !err;
}

bool SndPubkMessage::BufferToData(byte *buf, size_t max, size_t &finalSize, Crypto *c){
  bool err = false;
  finalSize = DeserializeData(buf, max, err, c, &pubkey, &first);
  return !err;
}

bool AuthClnMessage::DataToBuffer(byte *buf, size_t max, size_t &finalSize, Crypto *c){
  bool err = false;
  finalSize = SerializeData(buf, max, err, c, dh_key, nonce);
  return !err;
}

bool AuthClnMessage::BufferToData(byte *buf, size_t max, size_t &finalSize, Crypto *c){
  bool err = false;
  finalSize = DeserializeData(buf, max, err, c, &dh_key, &nonce);
  return !err;
}

bool SecMesgMessage::DataToBuffer(byte *buffer, size_t max, size_t &finalSize, Crypto *c){
  bool err = false;
  finalSize = SerializeData(buffer, max, err, c, buf);
  return !err;
}

bool SecMesgMessage::BufferToData(byte *buffer, size_t max, size_t &finalSize, Crypto *c){
  bool err = false;
  finalSize = DeserializeData(buffer, max, err, c, &buf);
  return !err;
}

bool InfMesgMessage::DataToBuffer(byte *buffer, size_t max, size_t &finalSize, Crypto *c){
  bool err = false;
  finalSize = SerializeData(buffer, max, err, c, info);
  return !err;
}

bool InfMesgMessage::BufferToData(byte *buffer, size_t max, size_t &finalSize, Crypto *c){
  bool err = false;
  finalSize = DeserializeData(buffer, max, err, c, &info);
  return !err;
}
