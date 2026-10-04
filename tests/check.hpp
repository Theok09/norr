#pragma once

#include <cstdio>
#include <cstdlib>

#define NORR_CHECK(condition)                                                        \
  do {                                                                               \
    if (!(condition)) {                                                              \
      std::fprintf(stderr, "CHECK failed: %s\n  at %s:%d\n", #condition, __FILE__,    \
                   __LINE__);                                                        \
      std::fflush(stderr);                                                           \
      std::abort();                                                                  \
    }                                                                                \
  } while (false)
