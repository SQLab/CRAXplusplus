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

const std::array<std::string, IOStates::LeakType::LAST> IOStates::s_leakTypes = {{
    "unknown", "code", "libc", "heap", "stack", "canary"
}};

IOStates::IOStates(CRAX &ctx)
    : m_ctx(ctx),
      m_canaryHookConnection() {
    // Install input state syscall hook.
    ctx.beforeSyscallHooks.connect(
            sigc::mem_fun(*this, &IOStates::inputStateHook));

    // Install output state syscall hook.
    ctx.afterSyscallHooks.connect(
            sigc::mem_fun(*this, &IOStates::outputStateHook));

    // If stack canary is enabled, install a hook to intercept canary values.
    if (m_ctx.getExploit().getElf().getChecksec().hasCanary) {
        m_canaryHookConnection = ctx.afterInstructionHooks.connect(
                sigc::mem_fun(*this, &IOStates::maybeInterceptStackCanary));

        ctx.beforeInstructionHooks.connect(
                sigc::mem_fun(*this, &IOStates::maybeTerminateState));
    }
}


void IOStates::inputStateHook(S2EExecutionState *inputState,
                              uint64_t nr_syscall,
                              uint64_t arg1,
                              uint64_t arg2,
                              uint64_t arg3,
                              uint64_t arg4,
                              uint64_t arg5,
                              uint64_t arg6) {
    if (nr_syscall != 0 || arg1 != STDIN_FILENO) {
        return;
    }

    m_ctx.setCurrentState(inputState);
    auto bufInfo = analyzeLeak(inputState, arg2, arg3);

    auto &os = log<WARN>();
    os << " ---------- Analyzing input state ----------\n";
    for (size_t i = 0; i < bufInfo.size(); i++) {
        os << "[" << IOStates::s_leakTypes[i] << "]: ";
        for (uint64_t offset : bufInfo[i]) {
            os << klee::hexval(offset) << ' ';
        }
        os << '\n';
    }

    for (uint64_t offset : bufInfo[IOStates::LeakType::CANARY]) {
        // Create input state snapshot.
        if (inputState->needToJumpToSymbolic()) {
            inputState->jumpToSymbolic();
        }

        S2EExecutor::StatePair sp = m_ctx.s2e()->getExecutor()->fork(*inputState);
        auto forkedState = dynamic_cast<S2EExecutionState *>(sp.second);

        log<WARN>()
            << "forked output state for leak detection (id="
            << forkedState->getID() << ")\n";

        // Hijack sys_read(0, buf, len), setting len to `value`.
        // Since the forked state is currently in symbolic mode,
        // we have to write a klee::ConstantExpr instead of uint64_t.
        ref<Expr> value = ConstantExpr::create(offset + 1, Expr::Int64);
        forkedState->regs()->write(CPU_OFFSET(regs[Register::X64::RDX]), value);
    }
}

void IOStates::outputStateHook(S2EExecutionState *outputState,
                               uint64_t nr_syscall,
                               uint64_t arg1,
                               uint64_t arg2,
                               uint64_t arg3,
                               uint64_t arg4,
                               uint64_t arg5,
                               uint64_t arg6) {
    if (nr_syscall != 1 || arg1 != STDOUT_FILENO) {
        return;
    }

    m_ctx.setCurrentState(outputState);
    auto leakInfo = detectLeak(outputState, arg2, arg3);

    auto &os = log<WARN>();
    os << "---------- Analyzing output state ----------\n";
    for (const auto &entry : leakInfo) {
        os << '(' << IOStates::s_leakTypes[entry.leakType]
            << ", " << klee::hexval(entry.bufIndex)
            << ", " << klee::hexval(entry.offset) << ")\n";

        if (entry.leakType == IOStates::LeakType::CANARY) {
            log<WARN>() << "[** WARN **] canary leaked!\n";
            m_ctx.getExploit().setCanaryLeakOffset(entry.bufIndex + 1);
        }
    }
}


void IOStates::maybeInterceptStackCanary(S2EExecutionState *state,
                                         const Instruction &i) {
    static bool hasReachedMain = false;

    if (i.address == m_ctx.getExploit().getElf().symbols()["main"]) {
        hasReachedMain = true;
    }

    if (hasReachedMain &&
        i.mnemonic == "mov" && i.opStr == "rax, qword ptr fs:[0x28]") {
        uint64_t canary = m_ctx.reg().readConcrete(Register::X64::RAX);
        m_ctx.getExploit().getElf().setCanary(canary);
        m_canaryHookConnection.disconnect();
        log<WARN>() << "Intercepted canary: " << klee::hexval(canary) << '\n';
    }
}

void IOStates::maybeTerminateState(S2EExecutionState *state,
                                   const Instruction &i) {
    if (i.address == m_ctx.getExploit().getElf().symbols()["__stack_chk_fail"]) {
        // XXX: If we disable forking instead of terminating the state here,
        // the forked output state will run endlessly. Why is that ?__?
        g_s2e->getExecutor()->terminateState(*state, "reached __stack_chk_fail@plt");
    }
}


std::array<std::vector<uint64_t>, IOStates::LeakType::LAST>
IOStates::analyzeLeak(S2EExecutionState *inputState, uint64_t buf, uint64_t len) {
    auto mapInfo = m_ctx.mem().getMapInfo(m_ctx.getTargetProcessPid());
    uint64_t canary = m_ctx.getExploit().getElf().getCanary();
    std::array<std::vector<uint64_t>, IOStates::LeakType::LAST> bufInfo;

    for (uint64_t i = 0; i < len; i += 8) {
        uint64_t value = u64(m_ctx.mem().readConcrete(buf + i, 8, /*concretize=*/false));
        //log<WARN>() << "addr = " << klee::hexval(buf + i) << " value = " << klee::hexval(value) << '\n';
        if (m_ctx.getExploit().getElf().getChecksec().hasCanary && value == canary) {
            bufInfo[LeakType::CANARY].push_back(i);
        } else {
            for (const auto &region : mapInfo) {
                if (value >= region.start && value <= region.end) {
                    bufInfo[getLeakType(region.image)].push_back(i);
                }
            }
        }
    }

    return bufInfo;
}

std::vector<IOStates::LeakInfo>
IOStates::detectLeak(S2EExecutionState *outputState, uint64_t buf, uint64_t len) {
    auto mapInfo = m_ctx.mem().getMapInfo(m_ctx.getTargetProcessPid());
    uint64_t canary = m_ctx.getExploit().getElf().getCanary();
    std::vector<IOStates::LeakInfo> leakInfo;

    for (uint64_t i = 0; i < len; i += 8) {
        uint64_t value = u64(m_ctx.mem().readConcrete(buf + i, 8, /*concretize=*/false));
        // log<WARN>() << "addr = " << klee::hexval(buf + i) << " value = " << klee::hexval(value) << '\n';
        if (m_ctx.getExploit().getElf().getChecksec().hasCanary && (value & ~0xff) == canary) {
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
