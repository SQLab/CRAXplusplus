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

#ifndef S2E_PLUGINS_CRAX_INPUT_STREAM_H
#define S2E_PLUGINS_CRAX_INPUT_STREAM_H

#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/BinaryByteStream.h>

#include <algorithm>

namespace s2e::plugins::crax {

// InputStream is a read-only, non-owning reference to a byte stream.
// It doesn't incur a copy for any read operation. Additionally,
// it keeps track of how many bytes have been read and how many bytes
// have been ignored.
//
// Note that InputStream::ignore() works similarly to std::istream::ignore().

class InputStream : public llvm::BinaryByteStream {
public:
    explicit InputStream(llvm::ArrayRef<uint8_t> data)
        : BinaryByteStream(data, llvm::support::endianness::little),
          m_nrBytesRead(),
          m_nrBytesIgnored() {}

    virtual ~InputStream() override = default;

    // Reads the next n bytes from the input stream.
    // If failed, the returned ArrayRef will be empty.
    [[nodiscard]]
    llvm::ArrayRef<uint8_t> read(uint64_t n) {
        llvm::ArrayRef<uint8_t> ret;
        n = std::min(n, getNrBytesRemaining());
        if (auto EC = readBytes(getNrBytesConsumed(), n, ret)) {
            return {};
        }
        m_nrBytesRead += n;
        return ret;
    }

    [[nodiscard]]
    llvm::ArrayRef<uint8_t> readAll() {
        return read(getNrBytesRemaining());
    }

    // Similar to std::istream::ignore(), this method extracts
    // the next n bytes from the input stream and discards them.
    // Note that the user must explicitly check the error code.
    [[nodiscard]]
    llvm::Error ignore(uint64_t n) {
        llvm::ArrayRef<uint8_t> dummy;
        if (auto EC = readBytes(getNrBytesConsumed(), n, dummy)) {
            return EC;
        }
        m_nrBytesIgnored += n;
        return llvm::Error::success();
    }


    [[nodiscard]]
    uint64_t getNrBytesConsumed() const {
        return m_nrBytesRead + m_nrBytesIgnored;
    }

    [[nodiscard]]
    uint64_t getNrBytesRemaining() const {
        return Data.size() - getNrBytesConsumed();
    }

    [[nodiscard]]
    uint64_t getNrBytesRead() const {
        return m_nrBytesRead;
    }

    [[nodiscard]]
    uint64_t getNrBytesIgnored() const {
        return m_nrBytesIgnored;
    }

private:
    uint64_t m_nrBytesRead;
    uint64_t m_nrBytesIgnored;
};


inline llvm::raw_ostream &operator<<(llvm::raw_ostream &os,
                                     const llvm::ArrayRef<uint8_t> &data) {
    for (auto byte : data) {
        os << byte;
    }
    return os;
}

}  // namespace s2e::plugins::crax

#endif  // S2E_PLUGINS_CRAX_INPUT_STREAM_H
