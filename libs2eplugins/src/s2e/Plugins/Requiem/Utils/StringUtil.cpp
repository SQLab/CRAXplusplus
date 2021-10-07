// Copyright (C) 2021-2022, Marco Wang
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

#include "StringUtil.h"

namespace s2e::plugins::requiem {

std::string toString(const std::istream &is) {
    std::stringstream ss;
    ss << is.rdbuf();
    return ss.str();
}

std::vector<std::string> split(const std::string &s, const char delim) {
    std::stringstream ss(s);
    std::vector<std::string> tokens;
    std::string token;

    while (std::getline(ss, token, delim)) {
        if (token.size()) {
            tokens.push_back(std::move(token));
        }
    }
    return tokens;
}

std::string join(const std::vector<std::string> &strings, const char delim) {
    std::stringstream ss;
    for (size_t i = 0; i < strings.size(); i++) {
        ss << strings[i];
        if (i != strings.size() - 1) {
            ss << delim;
        }
    }
    return ss.str();
}

void replace(std::string &s, const std::string &keyword, const std::string &newword) {
    std::string::size_type pos = s.find(keyword);

    while (pos != std::string::npos) {
        s.replace(pos, keyword.size(), newword);
        pos = s.find(keyword, pos + newword.size());
    }
}

std::string slice(const std::string &s, size_t start, size_t end) {
    // If `start` is out-of-bound, just let it fail,
    // since it indicates a programming error.
    size_t len;
    if (end != std::string::npos && end >= s.size()) {
        len = std::string::npos;
    }
    len = end - start;
    return s.substr(start, len);
}

void strip(std::string &s) {
  static const char* whitespace = " \n\r\t";
  s.erase(0, s.find_first_not_of(whitespace));
  s.erase(s.find_last_not_of(whitespace) + 1);
}

}  // namespace s2e::plugins::requiem
