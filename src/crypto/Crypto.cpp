#include <crypto/Crypto.h>


/*
  funcitons for debugging purpose
*/

void LOG_OPENSSL_ERRORS(){
  size_t error = ERR_get_error();
  while(error > 0){
    std::cout << "error: " << ERR_reason_error_string(error) << std::endl;
    error = ERR_get_error();
  }
}

void LOG_BUFFER(byte* buffer, size_t size){
  std::cout << std::hex << "log: ";
  for(size_t i = 0; i < size; i++)
    std::cout << (int)buffer[i] << " ";
  std::cout << std::dec << std::endl;
}

size_t Crypto::getEncryptSize(size_t in){
  if(cipher == NULL)
    return 0;
  size_t blkSize = EVP_CIPHER_block_size(cipher);
  return (1 + (in / blkSize)) * blkSize - 1;
}

size_t Crypto::getPubKeySize(){
  if(pubKey == NULL)
    return 0;
  return EVP_PKEY_size(pubKey);
}

size_t Crypto::getPrvKeySize(){
  if(prvKey == NULL)
    return 0;
  return EVP_PKEY_size(prvKey);
}

size_t Crypto::getHashSize(){
  if(hash == NULL)
    return 0;
  return EVP_MD_size(hash);
}

int Crypto::verifyCert(X509* cert){
  X509_STORE_CTX *ctx = X509_STORE_CTX_new();

  if(ctx == NULL || store == NULL)
    return 0;

  if( 1 != X509_STORE_CTX_init(ctx, store, cert, NULL))
    return 0;

  int ret = X509_verify_cert(ctx);
  X509_STORE_CTX_free(ctx);

  return ret;
}

EVP_PKEY* Crypto::loadPubKeyFromFile(const char* path, const char* psw){
  char* canon_file = realpath(path, NULL), temp[PATH_MAX + 1], *res;
  res = getcwd(temp, PATH_MAX + 1);

  if (!canon_file || !res || strncmp(canon_file, temp, strlen(temp)) != 0 || (psw != NULL && strlen(psw) > MAXPSWSIZE)){
    free(canon_file);
    return NULL;
  }


  EVP_PKEY* key;
  FILE* f = fopen(canon_file, "r");
  free(canon_file);

  if(f == NULL)
    return NULL;

  if(psw == NULL)
    key = PEM_read_PUBKEY(f, NULL, NULL, NULL);
  else{
    char *var_psw = new char[MAXPSWSIZE + 1];
    memcpy(var_psw, psw, strlen(psw) + 1);
    key = PEM_read_PUBKEY(f, NULL, NULL, var_psw);
    memset(var_psw, 0, MAXPSWSIZE + 1);
    delete[] var_psw;
  }

  fclose(f);

  return key;
}

EVP_PKEY* Crypto::loadPrvKeyFromFile(const char* path, const char* psw){
  char* canon_file = realpath(path, NULL), temp[PATH_MAX + 1], *res;
  res = getcwd(temp, PATH_MAX + 1);

  if (!canon_file || !res || strncmp(canon_file, temp, strlen(temp)) != 0 || (psw != NULL && strlen(psw) > MAXPSWSIZE)){
    free(canon_file);
    return NULL;
  }

  EVP_PKEY* key;
  FILE* f = fopen(canon_file, "r");
  free(canon_file);

  if(f == NULL)
    return NULL;

  if(psw == NULL)
    key = PEM_read_PrivateKey(f, NULL, NULL, NULL);
  else{
    char *var_psw = new char[MAXPSWSIZE + 1];
    memcpy(var_psw, psw, strlen(psw) + 1);
    key = PEM_read_PrivateKey(f, NULL, NULL, var_psw);
    memset(var_psw, 0, MAXPSWSIZE + 1);
    delete[] var_psw;
  }

  fclose(f);

  return key;
}

X509* Crypto::loadCertFromFile(const char* path){
  char* canon_file = realpath(path, NULL), temp[PATH_MAX + 1], *res;
  res = getcwd(temp, PATH_MAX + 1);

  if (!canon_file || !res || strncmp(canon_file, temp, strlen(temp)) != 0){
    free(canon_file);
    return NULL;
  }

  X509* cert;
  FILE* f = fopen(canon_file, "r");
  free(canon_file);

  if(f == NULL)
    return NULL;

  cert = PEM_read_X509(f, NULL, NULL, NULL);

  fclose(f);

  return cert;
}

X509_CRL* Crypto::loadCertCRLFromFile(const char* path){
  char* canon_file = realpath(path, NULL), temp[PATH_MAX + 1], *res;
  res = getcwd(temp, PATH_MAX + 1);

  if (!canon_file || !res || strncmp(canon_file, temp, strlen(temp)) != 0){
    free(canon_file);
    return NULL;
  }

  X509_CRL* crl;
  FILE* f = fopen(canon_file, "r");
  free(canon_file);

  if(f == NULL)
    return NULL;

  crl = PEM_read_X509_CRL(f, NULL, NULL, NULL);

  fclose(f);

  return crl;
}

int Crypto::pushHistory(void* buf, size_t size){
  EVP_MD_CTX *ctx;
  size_t hashSize = getHashSize();
  unsigned int outlen;

  ctx = EVP_MD_CTX_new();

  if(ctx == NULL)
    return 0;

  #undef handle_error
  #define handle_error(x) if((x) != 1){ EVP_MD_CTX_free(ctx); return 0; }

  // hashing the buf
  handle_error( EVP_DigestInit(ctx, getHash()) );
  handle_error( EVP_DigestUpdate(ctx, buf, size) );
  handle_error( EVP_DigestFinal(ctx, &historyDigest[hashSize], &outlen) );

  // hashing the previous history with buf
  handle_error( EVP_DigestInit(ctx, getHash()) );
  handle_error( EVP_DigestUpdate(ctx, historyDigest, 2 * hashSize) );
  handle_error( EVP_DigestFinal(ctx, historyDigest, &outlen) );


  memset(&historyDigest[hashSize], 0, hashSize);

  // historyDigest = H( historyDisgest | H(buf))
  EVP_MD_CTX_free(ctx);

  return 1;
}

EVP_PKEY* Crypto::generateECDHKey(){
  EVP_PKEY* dh_params = NULL;
  EVP_PKEY_CTX* pctx = NULL;

  pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);

  if(pctx == NULL)
    return NULL;

  #undef handle_error
  #define handle_error(x) if((x) != 1){ EVP_PKEY_CTX_free(pctx); return NULL; }

  // setting the Diffie-Hellman params for ECDH
  handle_error( EVP_PKEY_paramgen_init(pctx) );
  handle_error( EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) );
  handle_error( EVP_PKEY_paramgen(pctx, &dh_params) );

  EVP_PKEY_CTX_free(pctx);

  EVP_PKEY* prvkey = NULL;
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(dh_params, NULL);

  if(ctx == NULL){
    EVP_PKEY_free(dh_params);
    return NULL;
  }

  #undef handle_error
  #define handle_error(x) if((x) != 1){ EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(dh_params); return NULL; }

  // private key generation
  handle_error( EVP_PKEY_keygen_init(ctx) );
  handle_error( EVP_PKEY_keygen(ctx, &prvkey) );

  EVP_PKEY_free(dh_params);
  EVP_PKEY_CTX_free(ctx);

  return prvkey;
}

symkey_t Crypto::getEphemeralKey(EVP_PKEY* prvkey, EVP_PKEY* pubkey){
  symkey_t sharedkey, key;
  EVP_PKEY_CTX* ECctx = NULL;

  key.data = nullptr;
  key.size = 0;

  ECctx = EVP_PKEY_CTX_new(prvkey, NULL);

  if(ECctx == NULL)
    return key;

  #undef handle_error
  #define handle_error(x) if((x) != 1){ EVP_PKEY_CTX_free(ECctx); return key; }

  handle_error( EVP_PKEY_derive_init(ECctx) );

  handle_error( EVP_PKEY_derive_set_peer(ECctx, pubkey) );

  handle_error( EVP_PKEY_derive(ECctx, NULL, &sharedkey.size) );

  sharedkey.data = new byte[sharedkey.size];
  handle_error( EVP_PKEY_derive(ECctx, sharedkey.data, &sharedkey.size) );

  EVP_PKEY_CTX_free(ECctx);

  size_t keySize = EVP_CIPHER_key_length(this->getCipher()), hashSize = this->getHashSize();

  key.size = ((keySize % hashSize) == 0) ? keySize : (1 + keySize / hashSize) * hashSize;
  key.data = new byte[key.size];

  if(false == hashToSize(key.data, key.size, sharedkey.data, sharedkey.size)){
    delete[] sharedkey.data;
    delete[] key.data;
    key.data = nullptr;
    key.size = 0;
    return key;
  }


  delete[] sharedkey.data;
  return key;
}

int fakeBytes(unsigned char *buf, int num){
  memset(buf, 3, num);
  return 1;
}

int fakePseudoBytes(unsigned char *buf, int num){
  memset(buf, 3, num);
  return 1;
}

 int fakeStatus(){ return 1; }

void Crypto::loadOldPRAND(){
  RAND_set_rand_method(oldPRAND);
}

void Crypto::loadFakePRAND(){
  oldPRAND = RAND_get_rand_method();
  RAND_set_rand_method(&fakePRAND);
}

Crypto::Crypto(){
  cipher = nullptr;
  hash = nullptr;
  historyDigest = nullptr;

  RAND_poll();
  // load the RNG
  oldPRAND = RAND_get_rand_method();

  // create the constant-RNG
  fakePRAND.bytes = fakeBytes;
  fakePRAND.seed = oldPRAND->seed;
  fakePRAND.cleanup = oldPRAND->cleanup;
  fakePRAND.add = oldPRAND->add;
  fakePRAND.pseudorand = fakePseudoBytes;
  fakePRAND.status = fakeStatus;

  // initialize the store
  store = nullptr;
  //X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);

  iv.data = nullptr;
  iv.size = 0;

  counterRecv = 0;
  counterSend = 0;

  mode = PLAIN;
}

Crypto::~Crypto(){
  X509_STORE_free(store);
  delete[] historyDigest;
  if(iv.data)
    delete[] iv.data;
}

void Crypto::cleanup(){
  if(iv.data)
    memset(iv.data, 0, iv.size);
  if(symKey.data)
    memset(symKey.data, 0, symKey.size);
  counterRecv = 0;
  counterSend = 0;
  mode = PLAIN;
  clearHistory();
}

bool Crypto::hashToSize(byte *outbuf, size_t outlen, byte *inbuf, size_t inlen){
  EVP_MD_CTX *ctx;
  size_t i, ceilLen, hashSize = this->getHashSize();
  byte *finalSegment = new byte[hashSize];
  unsigned int hsh = hashSize;

  ceilLen = (outlen % hashSize == 0) ? outlen : (1 + outlen / hashSize) * hashSize;
  ctx = EVP_MD_CTX_new();

  if(ctx == NULL){
    std::cout << "ERROR: impossible to create a MD context" << std::endl;
    return false;
  }

  #undef handle_error
  #define handle_error(x) if((x) != 1){ EVP_MD_CTX_free(ctx); return false; }

  for(i = 0; i < ceilLen - hashSize; i += hashSize){
    handle_error( EVP_DigestInit(ctx, getHash()) );
    handle_error( EVP_DigestUpdate(ctx, inbuf, inlen) );
    handle_error( EVP_DigestUpdate(ctx, (void*)&i, sizeof(size_t)) );
    handle_error( EVP_DigestFinal(ctx, &outbuf[i], &hsh) );
  }

  handle_error( EVP_DigestInit(ctx, getHash()) );
  handle_error( EVP_DigestUpdate(ctx, inbuf, inlen) );
  handle_error( EVP_DigestUpdate(ctx, (void*)&i, sizeof(size_t)) );
  handle_error( EVP_DigestFinal(ctx, finalSegment, &hsh) );

  memcpy(&outbuf[i], finalSegment, (ceilLen == outlen) ? hashSize : ceilLen - outlen);

  EVP_MD_CTX_free(ctx);
  delete[] finalSegment;

  return true;
}

void Crypto::updateIV(){
  counterRecv += (!isSending);
  counterSend += ( isSending);
}
