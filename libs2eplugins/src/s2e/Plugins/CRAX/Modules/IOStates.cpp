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
#include <s2e/Plugins/CRAX/Pwnlib/Util.h>

#include <unistd.h>

#include "IOStates.h"

namespace s2e::plugins::crax {

IOStates::IOStates(CRAX &ctx)
    : m_ctx(ctx),
      m_canaryHookConnection() {
    // Install IOStates hook.
    ctx.beforeSyscallHooks.connect(
            sigc::mem_fun(*this, &IOStates::maybeAnalyzeState));

    // If stack canary is enabled, install a hook
    // to intercept canary values.
    if (m_ctx.getExploit().getElf().getChecksec().hasCanary) {
        m_canaryHookConnection = ctx.afterInstructionHooks.connect(
                sigc::mem_fun(*this, &IOStates::maybeInterceptStackCanary));
    }
}


void IOStates::maybeAnalyzeState(S2EExecutionState *state,
                                 uint64_t nr_syscall,
                                 uint64_t arg1,
                                 uint64_t arg2,
                                 uint64_t arg3,
                                 uint64_t arg4,
                                 uint64_t arg5,
                                 uint64_t arg6) {
    // XXX: don't hardcode the syscall numbers.
    if (nr_syscall == 0 && arg1 == STDIN_FILENO) {
        log<WARN>() << "input state here :)\n";
        analyzeLeak(state, arg2, arg3);

    } else if (nr_syscall == 1 && arg1 == STDOUT_FILENO) {
        log<WARN>() << "output state here :)\n";
        detectLeak(state, arg2, arg3);
    }
}

void IOStates::maybeInterceptStackCanary(S2EExecutionState *state,
                                         const Instruction &i) {
    if (i.mnemonic == "mov" && i.opStr == "rax, qword ptr fs:[0x28]") {
        // XXX: we should only intercept canary after main().
        uint64_t canary = m_ctx.reg().readConcrete(Register::X64::RAX);
        log<WARN>() << "Intercepted canary: " << klee::hexval(canary) << '\n';
        m_ctx.getExploit().getElf().setCanary(canary);
    }
}

std::vector<IOStates::LeakInfo>
IOStates::analyzeLeak(S2EExecutionState *inputState, uint64_t buf, uint64_t len) {
    auto mapInfo = m_ctx.mem().getMapInfo(m_ctx.getTargetProcessPid());
    uint64_t canary = m_ctx.getExploit().getElf().getCanary();
    std::vector<IOStates::LeakInfo> leakInfo;

    for (uint64_t i = 0; i < len; i += 8) {
        uint64_t value = u64(m_ctx.mem().readConcrete(buf + i, 8));
        log<WARN>() << "addr = " << klee::hexval(buf + i) << " value = " << klee::hexval(value) << '\n';
        if (value == canary) {
            log<WARN>() << "found canary on stack at buf + " << klee::hexval(i) << "\n";
            leakInfo.push_back({i, 0, LeakType::CANARY});
        } else {
            for (const auto &region : mapInfo) {
                if (value >= region.start && value <= region.end) {
                    leakInfo.push_back({i, value - region.start, getLeakType(region.image)});
                }
            }
        }
    }

    return leakInfo;
}

void IOStates::detectLeak(S2EExecutionState *outputState, uint64_t buf, uint64_t len) {

}


IOStates::LeakType IOStates::getLeakType(const std::string &image) const {
    if (image == m_ctx.getExploit().getElfFilename()) {
        return IOStates::LeakType::CODE;
    } else if (image == "[shared library]") {
        return IOStates::LeakType::LIBC;
    } else if (image == "[stack]") {
        return IOStates::LeakType::STACK;
    } else {
        return IOStates::LeakType::UNKNOWN;
    }
}

}  // namespace s2e::plugins::crax
