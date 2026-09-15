#pragma once

#include <cstdio>
#include <cstdlib>

// An always-on test check.
//
// `assert` is compiled out whenever NDEBUG is defined, which CMake does for
// both Release and RelWithDebInfo. A suite written with `assert` therefore
// verifies nothing in those build types while still reporting success, and a
// test that then dereferences what it "checked" crashes instead of failing
// cleanly. That is exactly what happened here: a release run reported 17 of 18
// binaries passing while none of them had actually checked anything.
//
// NORR_CHECK survives NDEBUG, so optimised builds test the optimised code.
// That matters beyond tidiness: optimisation changes behaviour, and the
// release build is what ships.
#define NORR_CHECK(condition)                                                        \
  do {                                                                               \
    if (!(condition)) {                                                              \
      std::fprintf(stderr, "CHECK failed: %s\n  at %s:%d\n", #condition, __FILE__,    \
                   __LINE__);                                                        \
      std::fflush(stderr);                                                           \
      std::abort();                                                                  \
    }                                                                                \
  } while (false)
