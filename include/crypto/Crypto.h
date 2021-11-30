#ifndef CRYPTO_H
#define CRYPTO_H

#include <var.h>
#include <openssl/x509.h>
#include <iostream>
#include <openssl/pem.h>
#include <openssl/hmac.h>
#include <cstring>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <unistd.h>
#include <dirent.h>
#include <utils.h>

extern void LOG_OPENSSL_ERRORS();

extern void LOG_BUFFER(byte* buf, size_t size);

enum CryptoModes{
  PLAIN   = 0,
  ENCRYPT = 1,
  SIGN    = 2,
  AUTH    = 4
};

class Crypto{
  EVP_PKEY *prvKey, *pubKey;
  symkey_t symKey;

  const EVP_CIPHER *cipher;
  const EVP_MD *hash;

  byte* historyDigest;
  buffer_t signature;
  EVP_MD_CTX* signatureCtx;

  const RAND_METHOD *oldPRAND;
  RAND_METHOD fakePRAND;

  X509_STORE* store;

  iv_t iv;
  uint64_t counterSend, counterRecv;
  bool isSending;

  CryptoModes mode;
public:
  Crypto();
  ~Crypto();

  bool initSignature();
  bool updateSignature(byte* inbuf, size_t inlen);
  bool finalizeSignature();

  buffer_t getSignature(){ return signature; };

  bool initVerifySignature();
  bool updateVerifySignature(byte* inbuf, size_t inlen);
  bool verifySignature(buffer_t toVerify);

  // methods for the store
  int addCert(X509* cert){ if(!store){store = X509_STORE_new();}; return X509_STORE_add_cert(store, cert); };
  int addCRL(X509_CRL* crl){ if(!store){store = X509_STORE_new();}; return X509_STORE_add_crl(store, crl); };
  int verifyCert(X509* cert);

  // set the default hash and cipher algorithms
  void setCipher(const EVP_CIPHER* cph){
    cipher = cph;

    if(iv.data)
      delete[] iv.data;

    iv.size = EVP_CIPHER_iv_length(cipher);
    iv.data = new byte[iv.size];
    memset(iv.data, 0, iv.size);
  };

  void setHash(const EVP_MD* hsh){
    hash = hsh;
    if(historyDigest != nullptr){
      delete[] historyDigest;
    }
    historyDigest = new byte[2 * getHashSize()];
    clearHistory();
  };


  void setMode(int _mode){ mode = (CryptoModes)_mode; }
  CryptoModes getMode(){ return mode; }

  // getter/setter methods
  const EVP_CIPHER * getCipher(){ return cipher; };
  const EVP_MD * getHash(){ return hash; };

  symkey_t getKey(){ return symKey; };
  void setKey(symkey_t key){ symKey = key; }


  EVP_PKEY* getPubKey(){ return pubKey; };
  void setPubKey(EVP_PKEY* key){ pubKey = key; };

  EVP_PKEY* getPrvKey(){ return prvKey; };
  void setPrvKey(EVP_PKEY* key){ prvKey = key; };

  void startSend(){ isSending = true; };
  void startRecv(){ isSending = false; };

  iv_t getIV(){
    uint64_t counter = hton64((isSending ? counterSend : counterRecv));
    hashToSize(iv.data, iv.size, (byte*)&counter, sizeof(uint64_t));
    return iv;
  };
  void updateIV();

  size_t getEncryptSize(size_t in);
  size_t getPubKeySize();
  size_t getPrvKeySize();
  size_t getHashSize();
  size_t getKeySize(){ return EVP_CIPHER_key_length(cipher); }

  // methods to add nonce to the sign and authenitcation
  int pushHistory(void* buf, size_t size);
  void clearHistory(){
    if(historyDigest == nullptr)
      return;
    memset(historyDigest, 0, getHashSize());
  };
  byte* getHistoryDigest(){ return historyDigest; };

  // methods to load data from files
  EVP_PKEY* loadPubKeyFromFile(const char* path, const char* psw = NULL);
  EVP_PKEY* loadPrvKeyFromFile(const char* path, const char* psw = NULL);

  X509* loadCertFromFile(const char* path);
  X509_CRL* loadCertCRLFromFile(const char* path);

  // Diffie-Hellman methods
  symkey_t getEphemeralKey(EVP_PKEY* prvkey, EVP_PKEY* pubkey);
  static EVP_PKEY* generateECDHKey();

  // methods to load a Fake (constant) or a "true" RNG
  void loadFakePRAND();
  void loadOldPRAND();

  bool hashToSize(byte *outbuf, size_t outlen, byte *inbuf, size_t inlen);

  void cleanup();

  void receiver(){ counterSend = 0; counterRecv = ((uint64_t)1 << 63);};
  void transmitter(){ counterSend = ((uint64_t)1 << 63); counterRecv = 0; };
};

#endif
