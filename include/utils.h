#ifndef UTILS_H
#define UTILS_H

#include <exception>
#include <stdlib.h>
#include <signal.h>
#include <stdio.h>
#include <setjmp.h>
#include <endian.h>
#include "var.h"

enum ERROR{
  GENERIC,
  IOSIZE,
};

class Exception : public std::exception{
  size_t line = 0;
  const char* file, *func;
  ERROR err;
public:
  Exception(ERROR _err, size_t _line = 0, const char* _file = nullptr, const char* _func = nullptr){
    line = _line;
    func = _func;
    file = _file;
    err  = _err;
  }

  const char * what() const throw(){
    return "C++ Exception";
  }
};

extern uint64_t hton64(uint64_t value);
extern uint64_t ntoh64(uint64_t value);

#endif
