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

#include "Algorithm.h"

namespace s2e::plugins::requiem {

std::vector<uint64_t> kmp(const std::vector<uint8_t> &haystack,
                          const std::vector<uint8_t> &needle) {
    // Compute failure function.
    int tail = -1;
    std::vector<uint64_t> ret;
    std::vector<int> failure(needle.size(), -1);

    for (size_t r = 1, l = -1; r < needle.size(); r++) {
        while (l != -1 && needle[l + 1] != needle[r]) {
            l = failure[l];
        }

        if (needle[l + 1] == needle[r]) {
            failure[r] = ++l;
        }
    }

    // Search needle in haystasck.
    for (size_t i = 0; i < haystack.size(); i++) {
        while (tail != -1 && haystack[i] != needle[tail + 1]) {
            tail = failure[tail];
        }

        if (haystack[i] == needle[tail + 1]) {
            tail++;
        }

        if (tail == needle.size() - 1) {
            ret.push_back(i - tail);
            continue;
        }
    }

    return ret;
}


}  // namespace s2e::plugins::requiem
