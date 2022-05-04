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

#include <s2e/Plugins/CRAX/CRAX.h>

#include "GuestOutput.h"

#define SYS_WRITE  0x01
#define SYS_WRITEV 0x14

using namespace klee;

namespace {

struct iovec {
    void *iov_base;  // starting address
    size_t iov_len;  // number of bytes to transfer
};

}  // namespace

namespace s2e::plugins::crax {

GuestOutput::GuestOutput() : Module() {
    g_crax->afterSyscall.connect(
            sigc::mem_fun(*this, &GuestOutput::onWrite));

    g_crax->afterSyscall.connect(
            sigc::mem_fun(*this, &GuestOutput::onWritev));
}


// ssize_t write(int fd, const void *buf, size_t count);
void GuestOutput::onWrite(S2EExecutionState *state,
                          const SyscallCtx &syscall) {
    if (syscall.nr != SYS_WRITE || !isValidFd(syscall.arg1)) {
        return;
    }

    g_crax->setCurrentState(state);

    std::vector<uint8_t> bytes = mem().readConcrete(syscall.arg2, syscall.ret, /*concretize=*/false);
    write(syscall.arg1, bytes.data(), bytes.size());
}

// ssize_t writev(int fd, const struct iovec *iov, int iovcnt);
void GuestOutput::onWritev(S2EExecutionState *state,
                           const SyscallCtx &syscall) {
    if (syscall.nr != SYS_WRITEV || !isValidFd(syscall.arg1)) {
        return;
    }

    g_crax->setCurrentState(state);

    for (uint64_t i = 0; i < syscall.arg3; i++) {
        uint64_t iovAddr = syscall.arg2 + i * sizeof(iovec);
        std::vector<uint8_t> iovBytes = mem().readConcrete(iovAddr, sizeof(iovec));

        iovec *iov = reinterpret_cast<iovec *>(iovBytes.data());
        uint64_t addr = reinterpret_cast<uint64_t>(iov->iov_base);

        std::vector<uint8_t> bytes = mem().readConcrete(addr, iov->iov_len, /*concretize=*/false);
        write(syscall.arg1, bytes.data(), bytes.size());
    }
}

}  // namespace s2e::plugins::crax
