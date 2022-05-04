// Copyright 2021-2022 Software Quality Laboratory, NYCU.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifndef S2E_PLUGINS_CRAX_STRING_UTIL_H
#define S2E_PLUGINS_CRAX_STRING_UTIL_H

#include <cstring>
#include <memory>
#include <istream>
#include <sstream>
#include <string>
#include <vector>
#include <type_traits>

namespace s2e::plugins::crax {

template <typename... Args>
std::string format(const std::string &fmt, Args &&...args) {
  // std::snprintf(dest, n, fmt, ...) returns the number of chars
  // that will be actually written into `dest` if `n` is large enough,
  // not counting the terminating null character.
  const int bufSize
    = 1 + std::snprintf(nullptr, 0, fmt.c_str(), std::forward<Args>(args)...);

  const auto buf = std::make_unique<char[]>(bufSize);
  std::memset(buf.get(), 0x00, bufSize);

  return (std::snprintf(buf.get(), bufSize, fmt.c_str(),
          std::forward<Args>(args)...) > 0) ? std::string(buf.get()) : "";
}

// A byte string is a sequence of bytes, such as b'\xef\xbe\xad\xde'
// which represents 0xdeadbeef.
// input:  {0xef, 0xbe, 0xad, 0xde}
// output: \xef\xbe\xad\xde
template <typename InputIt>
std::string toByteString(InputIt first, InputIt last) {
    std::string ret;
    for (auto it = first; it != last; it++) {
        ret += format("\\x%02x", *it);
    }
    return ret;
}

template <typename T>
std::string streamToString(const T &s) {
    std::stringstream ss;
    ss << s.rdbuf();
    return ss.str();
}


std::vector<std::string> split(const std::string &s, const char delim);
std::vector<std::string> split(const std::string &s, const std::string &delim);

std::string join(const std::vector<std::string> &strings, const char delim);
std::string replace(std::string s, const std::string &keyword, const std::string &newword);
std::string slice(std::string s, size_t start, size_t end = std::string::npos);  // [start, end)
std::string strip(std::string s);
std::string ljust(std::string s, size_t size, char c);

bool startsWith(const std::string &s, const std::string &prefix);
bool endsWith(const std::string &s, const std::string &suffix);
bool isNumString(const std::string &s);

}  // namespace s2e::plugins::crax

#endif  // S2E_PLUGINS_CRAX_STRING_UTIL_H
