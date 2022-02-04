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

#include <cassert>
#include <algorithm>

#include "Util.h"

namespace s2e::plugins::crax {

std::vector<uint8_t> p64(uint64_t value) {
    uint64_t bitmask = 0xff;
    std::vector<uint8_t> ret(8);

    for (int i = 0; i < 8; i++) {
        ret[i] = (value & bitmask) >> i * 8;
        if (i != 7) {
            bitmask <<= 8;
        }
    }
    return ret;
}

uint64_t u64(const std::vector<uint8_t> &bytes) {
    assert(bytes.size() <= 8);

    std::vector<uint8_t> ret(8, 0);
    std::copy(bytes.begin(), bytes.end(), ret.begin());

    return *reinterpret_cast<uint64_t *>(ret.data());
}

}  // namespace s2e::plugins::crax
