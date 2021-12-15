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

#include <unistd.h>

#include "IOStates.h"

namespace s2e::plugins::crax {

IOStates::IOStates(CRAX &ctx)
    : m_ctx(ctx) {
    ctx.beforeSyscallHooks.connect(
            sigc::mem_fun(*this, &IOStates::maybeAnalyzeState));
}


void IOStates::maybeAnalyzeState(S2EExecutionState *state,
                                 uint64_t rax,
                                 uint64_t rdi,
                                 uint64_t rsi,
                                 uint64_t rdx,
                                 uint64_t r10,
                                 uint64_t r8,
                                 uint64_t r9) {
    // XXX: don't hardcode the syscall numbers.
    if (rax == 0 && rdi == STDIN_FILENO) {
        m_ctx.log<WARN>() << "input state here :)\n";
        analyzeLeak(state, rax, rdi, rsi, rdx, r10, r8, r9);
    } else if (rax == 1 && rdi == STDOUT_FILENO) {
        m_ctx.log<WARN>() << "output state here :)\n";
    }
}

void IOStates::analyzeLeak(S2EExecutionState *inputState,
                           uint64_t rax,
                           uint64_t rdi,
                           uint64_t rsi,
                           uint64_t rdx,
                           uint64_t r10,
                           uint64_t r8,
                           uint64_t r9) {

}

void IOStates::detectLeak(S2EExecutionState *outputState,
                          uint64_t rax,
                          uint64_t rdi,
                          uint64_t rsi,
                          uint64_t rdx,
                          uint64_t r10,
                          uint64_t r8,
                          uint64_t r9) {

}

}  // namespace s2e::plugins::crax
