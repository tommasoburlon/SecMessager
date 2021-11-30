#ifndef VAR_H
#define VAR_H

#include <stdint.h>
#include <cstddef>
#include <openssl/pem.h>

#define MAXPSWSIZE 50
#define USERNAME_SIZE 16
#define LIST_SIZE 16

typedef uint8_t byte;
typedef unsigned __int128 nonce_t;
typedef uint16_t msglen_t;

struct symkey_t{
  byte* data;
  size_t size;
};

struct iv_t{
  byte* data;
  size_t size;
};

struct username_t{ char data[USERNAME_SIZE]; };

struct usernamelist_t{ username_t data[LIST_SIZE]; };

struct dh_key_t{ EVP_PKEY* data; };

struct ec_key_t{ EVP_PKEY* data; };

struct buffer_t{ byte* data; msglen_t size;};

extern void LOG(const char* ch);

#endif
