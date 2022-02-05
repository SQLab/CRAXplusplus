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

#ifndef S2E_PLUGINS_CRAX_PSEUDO_INPUT_STREAM_H
#define S2E_PLUGINS_CRAX_PSEUDO_INPUT_STREAM_H

#include "InputStream.h"

namespace s2e::plugins::crax {

class PseudoInputStream : public InputStream {
public:
    explicit PseudoInputStream(llvm::ArrayRef<uint8_t> data)
        : InputStream(data),
          m_nrBytesSkipped() {}

    virtual ~PseudoInputStream() override = default;

    // Simulates the act of reading n bytes from the input stream.
    // This is only used during exploit generation.
    void skip(uint64_t n) {
        m_nrBytesSkipped += n;
    }


    [[nodiscard]]
    uint64_t getNrBytesSkipped() const {
        return m_nrBytesSkipped;
    }

private:
    uint64_t m_nrBytesSkipped;
};

}  // namespace s2e::plugins::crax

#endif  // S2E_PLUGINS_CRAX_PSEUDO_INPUT_STREAM_H
