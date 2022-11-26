//
// Created by jabin on 2022/11/26.
//

#ifndef ANDROIDEXECUTABLE_STRINGPRINTF_H
#define ANDROIDEXECUTABLE_STRINGPRINTF_H

#include <stdio.h>
#include <string>

// These printf-like functions are implemented in terms of vsnprintf, so they
// use the same attribute for compile-time format string checking.

// Returns a string corresponding to printf-like formatting of the arguments.
std::string StringPrintf(const char* fmt, ...) __attribute__((__format__(__printf__, 1, 2)));

// Appends a printf-like formatting of the arguments to 'dst'.
void StringAppendF(std::string* dst, const char* fmt, ...)
__attribute__((__format__(__printf__, 2, 3)));

// Appends a printf-like formatting of the arguments to 'dst'.
void StringAppendV(std::string* dst, const char* format, va_list ap)
__attribute__((__format__(__printf__, 2, 0)));

#endif //ANDROIDEXECUTABLE_STRINGPRINTF_H
