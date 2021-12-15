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

#ifndef S2E_PLUGINS_CRAX_IO_STATES_H
#define S2E_PLUGINS_CRAX_IO_STATES_H

#include <s2e/S2EExecutionState.h>

namespace s2e::plugins::crax {

// Forward declaration
class CRAX;

// This is an implementation of "IOState" from balsn's LAEG.
class IOStates {
public:
    IOStates(CRAX &ctx);

    void maybeAnalyzeState(S2EExecutionState *inputState,
                           uint64_t rax,
                           uint64_t rdi,
                           uint64_t rsi,
                           uint64_t rdx,
                           uint64_t r10,
                           uint64_t r8,
                           uint64_t r9);

    // Called at input states.
    void analyzeLeak(S2EExecutionState *inputState,
                     uint64_t rax,
                     uint64_t rdi,
                     uint64_t rsi,
                     uint64_t rdx,
                     uint64_t r10,
                     uint64_t r8,
                     uint64_t r9);

    // Called at output states.
    void detectLeak(S2EExecutionState *outputState,
                    uint64_t rax,
                    uint64_t rdi,
                    uint64_t rsi,
                    uint64_t rdx,
                    uint64_t r10,
                    uint64_t r8,
                    uint64_t r9);

private:
    CRAX &m_ctx;
    //uint64_t m_stackCanary;
};

}  // namespace s2e::plugins::crax

#endif  // S2E_PLUGINS_CRAX_IO_STATES_H
