#include <utils.h>


uint64_t hton64(uint64_t value){
  return htobe64(value);
}

uint64_t ntoh64(uint64_t value){
  return be64toh(value);
}
