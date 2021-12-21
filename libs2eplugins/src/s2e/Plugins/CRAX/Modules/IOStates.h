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

#include <array>
#include <string>
#include <vector>

namespace s2e::plugins::crax {

// Forward declaration
class CRAX;


// This is an implementation of "IOState" from balsn's LAEG.
class IOStates {
public:
    enum LeakType {
        UNKNOWN,
        CODE,
        LIBC,
        HEAP,
        STACK,
        CANARY,
        LAST
    };

    struct LeakInfo {
        uint64_t bufIndex;
        uint64_t offset;
        LeakType leakType;
    };


    explicit IOStates(CRAX &ctx);

    void inputStateHook(S2EExecutionState *inputState,
                        uint64_t nr_syscall,
                        uint64_t arg1,
                        uint64_t arg2,
                        uint64_t arg3,
                        uint64_t arg4,
                        uint64_t arg5,
                        uint64_t arg6);

    void outputStateHook(S2EExecutionState *outputState,
                         uint64_t nr_syscall,
                         uint64_t arg1,
                         uint64_t arg2,
                         uint64_t arg3,
                         uint64_t arg4,
                         uint64_t arg5,
                         uint64_t arg6);


    void maybeInterceptStackCanary(S2EExecutionState *state,
                                   const Instruction &i);

    void maybeDisableForking(S2EExecutionState *state,
                             const Instruction &i);


    // Called at input states.
    [[nodiscard]]
    std::array<std::vector<uint64_t>, IOStates::LeakType::LAST>
    analyzeLeak(S2EExecutionState *inputState, uint64_t buf, uint64_t len);

    // Called at output states.
    [[nodiscard]]
    std::vector<IOStates::LeakInfo>
    detectLeak(S2EExecutionState *outputState, uint64_t buf, uint64_t len);


    static const std::array<std::string, LeakType::LAST> s_leakTypes;

private:
    LeakType getLeakType(const std::string &image) const;

    CRAX &m_ctx;
    sigc::connection m_canaryHookConnection;
};

}  // namespace s2e::plugins::crax

#endif  // S2E_PLUGINS_CRAX_IO_STATES_H
