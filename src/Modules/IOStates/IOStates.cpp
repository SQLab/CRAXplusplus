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
#include <s2e/Plugins/CRAX/Utils/StringUtil.h>

#include <unistd.h>

#include "IOStates.h"

using namespace klee;

namespace s2e::plugins::crax {

const std::array<std::string, IOStates::LeakType::LAST> IOStates::s_leakTypes = {{
    "unknown", "code", "libc", "heap", "stack", "canary"
}};


IOStates::IOStates()
    : Module(),
      m_canary(),
      m_leakTargets(),
      m_userSpecifiedStateInfoList() {
    // Try to initialize user-specified state info list from the config.
    initUserSpecifiedStateInfoList();

    // Install input state syscall hook.
    g_crax->beforeSyscall.connect(
            sigc::mem_fun(*this, &IOStates::inputStateHookTopHalf));

    g_crax->afterSyscall.connect(
            sigc::mem_fun(*this, &IOStates::inputStateHookBottomHalf));

    // Install output state syscall hook.
    g_crax->afterSyscall.connect(
            sigc::mem_fun(*this, &IOStates::outputStateHook));

    // Determine which base address(es) must be leaked
    // according to checksec of the target binary.
    const auto &checksec = g_crax->getExploit().getElf().getChecksec();
    if (checksec.hasCanary) {
        m_leakTargets.push_back(IOStates::LeakType::CANARY);
    }
    if (checksec.hasPIE) {
        m_leakTargets.push_back(IOStates::LeakType::CODE);
    }
    // XXX: ASLR -> libc

    // If stack canary is enabled, install a hook to intercept canary values.
    if (checksec.hasCanary) {
        g_crax->afterInstruction.connect(
                sigc::mem_fun(*this, &IOStates::maybeInterceptStackCanary));

        g_crax->beforeInstruction.connect(
                sigc::mem_fun(*this, &IOStates::onStackChkFailed));
    }

    // If either stack canary or PIE is enabled, install a hook
    // to suppress native S2E state forks in order to avoid state explosion.
    if (checksec.hasCanary || checksec.hasPIE) {
        g_crax->onStateForkModuleDecide.connect(
                sigc::mem_fun(*this, &IOStates::onStateForkModuleDecide));
    }

    g_crax->beforeExploitGeneration.connect(
            sigc::mem_fun(*this, &IOStates::beforeExploitGeneration));
}

std::string IOStates::State::toString() const {
    std::string ret;

    for (size_t i = 0; i < stateInfoList.size(); i++) {
        const auto &info = stateInfoList[i];

        if (const auto stateInfo = std::get_if<InputStateInfo>(&info)) {
            ret += 'i';
            ret += std::to_string(stateInfo->offset);
        } else if (const auto stateInfo = std::get_if<OutputStateInfo>(&info)) {
            ret += 'o';
            if (stateInfo->valid) {
                ret += std::to_string(stateInfo->bufIndex);
            }
        }

        if (i != stateInfoList.size() - 1) {
            ret += ',';
        }
    }
    return ret;
}

void IOStates::initUserSpecifiedStateInfoList() {
    std::string str = g_s2e->getConfig()->getString(getConfigKey() + ".stateInfoList");
    log<INFO>() << "User-specified StateInfoList: " << str << '\n';

    if (str.empty()) {
        return;
    }

    // Parse the string into state info list.
    for (const auto &s : split(str, ',')) {
        if (s[0] == 'i') {
            assert(s.size() > 1);
            InputStateInfo stateInfo;
            stateInfo.offset = std::stoull(s.substr(1));
            m_userSpecifiedStateInfoList.push_back(std::move(stateInfo));

        } else if (s[0] == 'o') {
            OutputStateInfo stateInfo;
            stateInfo.valid = false;
            if (s.size() > 1) {
                stateInfo.bufIndex = std::stoull(s.substr(1));
            }
            m_userSpecifiedStateInfoList.push_back(std::move(stateInfo));

        } else {
            pabort("Corrupted stateInfoList provided.");
        }
    }
}


void IOStates::print() const {
    auto modState = g_crax->getPluginModuleState(g_crax->getCurrentState(), this);

    auto &os = log<WARN>();
    os << "Dumping IOStates: [";

    for (size_t i = 0; i < modState->stateInfoList.size(); i++) {
        if (const auto &inputStateInfo = std::get_if<InputStateInfo>(&modState->stateInfoList[i])) {
            os << "input";
        } else {
            os << "output";
        }
        if (i != modState->stateInfoList.size() - 1) {
            os << ", ";
        }
    }
    os << "]\n";
}

void IOStates::inputStateHookTopHalf(S2EExecutionState *inputState,
                                     SyscallCtx &syscall) {
    if (syscall.nr != 0 || syscall.arg1 != STDIN_FILENO) {
        return;
    }

    g_crax->setCurrentState(inputState);
    auto bufInfo = analyzeLeak(inputState, syscall.arg2, syscall.arg3);

    auto &os = log<WARN>();
    os << " ---------- Analyzing input state ----------\n";
    for (size_t i = 0; i < bufInfo.size(); i++) {
        os << "[" << IOStates::s_leakTypes[i] << "]: ";
        for (uint64_t offset : bufInfo[i]) {
            os << hexval(offset) << ' ';
        }
        os << '\n';
    }


    auto modState = g_crax->getPluginModuleState(inputState, this);

    if (modState->currentLeakTargetIdx >= m_leakTargets.size()) {
        log<WARN>() << "No more leak targets :^)\n";
        return;
    }

    IOStates::LeakType currentLeakType
        = m_leakTargets[modState->currentLeakTargetIdx];

    log<WARN>() << "Current leak target: " << s_leakTypes[currentLeakType] << '\n';

    if (bufInfo[currentLeakType].empty()) {
        log<WARN>() << "No leak targets in current input state.\n";
        return;
    }

    // If the user has specified a state info list in s2e-config.lua,
    // then we'll use the offsets provided by the user instead of
    // forking states for each possible offsets.
    if (m_userSpecifiedStateInfoList.size()) {
        size_t idx = modState->stateInfoList.size();
        assert(idx < m_userSpecifiedStateInfoList.size() &&
               "user-specified state info list out-of-bound...");

        InputStateInfo stateInfo
            = std::get<InputStateInfo>(m_userSpecifiedStateInfoList[idx]);

        ref<Expr> ce = ConstantExpr::create(stateInfo.offset, Expr::Int64);
        reg().writeSymbolic(Register::X64::RDX, ce);
        return;
    }

    // For each offset, fork a new state
    // XXX: Optimize this with a custom searcher (?)
    for (uint64_t offset : bufInfo[currentLeakType]) {
        // If we're leaking the canary, then we need to overwrite
        // the least significant bit of the canary, so offset++.
        if (currentLeakType == IOStates::LeakType::CANARY) {
            offset++;
        }

        S2EExecutionState *forkedState = g_crax->fork(*inputState);

        log<WARN>()
            << "Forked a new state for offset " << hexval(offset)
            << " (id=" << forkedState->getID() << ")\n";

        // Hijack sys_read(0, buf, len), setting len to `value`.
        // Note that the forked state is currently in symbolic mode,
        // so we have to write a klee::ConstantExpr instead of uint64_t.
        ref<Expr> ce = ConstantExpr::create(offset, Expr::Int64);
        reg(forkedState).writeSymbolic(Register::X64::RDX, ce);

        auto forkedModState = g_crax->getPluginModuleState(forkedState, this);
        forkedModState->leakableOffset = offset;
    }
}

void IOStates::inputStateHookBottomHalf(S2EExecutionState *inputState,
                                        const SyscallCtx &syscall) {
    if (syscall.nr != 0 || syscall.arg1 != STDIN_FILENO) {
        return;
    }

    g_crax->setCurrentState(inputState);

    std::vector<uint8_t> buf
        = mem().readConcrete(syscall.arg2, syscall.arg3, /*concretize=*/false);

    auto modState = g_crax->getPluginModuleState(inputState, this);

    InputStateInfo stateInfo;
    stateInfo.buf = std::move(buf);

    if (modState->leakableOffset) {
        // `inputStateHookBottomHalf()` -> `analyzeLeak()` has found
        // something that can be leaked and stored it in `modState->leakableOffset`.
        stateInfo.offset = modState->leakableOffset;
    } else {
        // Nothing to leak, set the offset as the original length of sys_read().
        stateInfo.offset = syscall.arg3;
    }

    modState->leakableOffset = 0;
    modState->lastInputStateInfoIdx = modState->stateInfoList.size();
    modState->stateInfoList.push_back(std::move(stateInfo));
}

void IOStates::outputStateHook(S2EExecutionState *outputState,
                               const SyscallCtx &syscall) {
    if (syscall.nr != 1 || syscall.arg1 != STDOUT_FILENO) {
        return;
    }

    g_crax->setCurrentState(outputState);

    auto outputStateInfoList = detectLeak(outputState, syscall.arg2, syscall.arg3);
    auto modState = g_crax->getPluginModuleState(outputState, this);

    // If the user has specified a state info list in s2e-config.lua,
    // then we should check if the leaked data's offset is really the same
    // as what user has claimed.
    if (m_userSpecifiedStateInfoList.size()) {
        size_t idx = modState->stateInfoList.size();
        assert(idx < m_userSpecifiedStateInfoList.size() &&
               "user-specified state info list out-of-bound...");

        OutputStateInfo stateInfo
            = std::get<OutputStateInfo>(m_userSpecifiedStateInfoList[idx]);

        if (stateInfo.valid) {
            assert(stateInfo.bufIndex == outputStateInfoList.front().bufIndex &&
                   "OutputStateInfo bufIndex mismatch!?");
        }
    }

    OutputStateInfo stateInfo;
    stateInfo.valid = false;

    if (outputStateInfoList.size()) {
        stateInfo.valid = true;
        stateInfo.bufIndex = outputStateInfoList.front().bufIndex;
        stateInfo.baseOffset = outputStateInfoList.front().baseOffset;
        stateInfo.leakType = outputStateInfoList.front().leakType;

        log<WARN>()
            << "*** WARN *** Detected leak: ("
            << IOStates::s_leakTypes[stateInfo.leakType] << ", "
            << hexval(stateInfo.bufIndex) << ", "
            << hexval(stateInfo.baseOffset) << ")\n";

        modState->currentLeakTargetIdx++;
    }

    modState->stateInfoList.push_back(std::move(stateInfo));
}


void IOStates::maybeInterceptStackCanary(S2EExecutionState *state,
                                         const Instruction &i) {
    static bool hasReachedMain = false;

    // If we've already intercepted the canary of the target ELF,
    // then we don't need to proceed anymore.
    if (m_canary) {
        return;
    }

    if (i.address == g_crax->getExploit().getElf().getRuntimeAddress("main")) {
        hasReachedMain = true;
    }

    if (hasReachedMain &&
        i.mnemonic == "mov" && i.opStr == "rax, qword ptr fs:[0x28]") {
        uint64_t canary = reg().readConcrete(Register::X64::RAX);
        m_canary = canary;

        log<WARN>()
            << '[' << hexval(i.address) << "] "
            << "Intercepted canary: " << hexval(canary) << '\n';
    }
}

void IOStates::onStackChkFailed(S2EExecutionState *state,
                                const Instruction &i) {
    const uint64_t stackChkFailPlt
        = g_crax->getExploit().getElf().getRuntimeAddress("__stack_chk_fail");

    if (i.address == stackChkFailPlt) {
        // The program has reached __stack_chk_fail and
        // there's no return, so kill it.
        g_s2e->getExecutor()->terminateState(*state, "reached __stack_chk_fail@plt");
    }
}

void IOStates::onStateForkModuleDecide(S2EExecutionState *state,
                                       const ref<Expr> &__condition,
                                       bool &allowForking) {
    // If S2E native forking is enabled, then it will automatically fork
    // at canary check.
    if (!g_crax->isNativeForkingDisabled()) {
        return;
    }

    g_crax->setCurrentState(state);

    // If the current branch instruction is the one before `call __stack_chk_fail@plt`,
    // then allow it to fork the current state.
    //
    // -> 401289:       74 05                   je     401290 <main+0xa2>
    //    40128b:       e8 20 fe ff ff          call   4010b0 <__stack_chk_fail@plt>
    //    401290:       c9                      leave
    uint64_t pc = state->regs()->getPc();
    std::optional<Instruction> i = disas().disasm(pc);  
    assert(i && "Disassemble failed?");

    // Look ahead the next instruction.
    if (!g_crax->isCallSiteOf(pc + i->size, "__stack_chk_fail")) {
        allowForking = false;
        return;
    }

    log<WARN>() << "Allowing fork before __stack_chk_fail@plt\n";
    allowForking &= true;

    if (uint64_t canary = g_crax->getUserSpecifiedCanary()) {
        log<WARN>()
            << "Constraining canary to " << hexval(canary)
            << " as requested.\n";

        // Hijack branch condition.
        assert(__condition);
        auto &condition = const_cast<ref<Expr> &>(__condition);

        uint64_t rbp = reg().readConcrete(Register::X64::RBP);
        condition = EqExpr::create(mem().readSymbolic(rbp - 8, Expr::Int64),
                                   ConstantExpr::create(canary, Expr::Int64));
    }
}

void IOStates::beforeExploitGeneration(S2EExecutionState *state) {
    auto modState = g_crax->getPluginModuleState(state, this);

    if (modState->lastInputStateInfoIdxBeforeFirstSymbolicRip == -1) {
        for (int i = modState->stateInfoList.size() - 1; i >= 0; i--) {
            const auto& info = modState->stateInfoList[i];
            if (const auto inputStateInfo = std::get_if<InputStateInfo>(&info)) {
                modState->lastInputStateInfoIdxBeforeFirstSymbolicRip = i;
                break;
            }
        }
    }
}


std::array<std::vector<uint64_t>, IOStates::LeakType::LAST>
IOStates::analyzeLeak(S2EExecutionState *inputState, uint64_t buf, uint64_t len) {
    auto mapInfo = mem().getMapInfo();
    uint64_t canary = m_canary;
    std::array<std::vector<uint64_t>, IOStates::LeakType::LAST> bufInfo;

    for (uint64_t i = 0; i < len; i += 8) {
        uint64_t value = u64(mem().readConcrete(buf + i, 8, /*concretize=*/false));
        //log<WARN>() << "addr = " << hexval(buf + i) << " value = " << hexval(value) << '\n';
        if (g_crax->getExploit().getElf().getChecksec().hasCanary && value == canary) {
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

std::vector<IOStates::OutputStateInfo>
IOStates::detectLeak(S2EExecutionState *outputState, uint64_t buf, uint64_t len) {
    auto mapInfo = mem().getMapInfo();
    uint64_t canary = m_canary;
    std::vector<IOStates::OutputStateInfo> leakInfo;

    for (uint64_t i = 0; i < len; i += 8) {
        uint64_t value = u64(mem().readConcrete(buf + i, 8, /*concretize=*/false));
        //log<WARN>() << "addr = " << hexval(buf + i) << " value = " << hexval(value) << '\n';
        IOStates::OutputStateInfo info;
        info.valid = true;

        if (g_crax->getExploit().getElf().getChecksec().hasCanary && (value & ~0xff) == canary) {
            info.bufIndex = i + 1;
            info.baseOffset = 0;
            info.leakType = LeakType::CANARY;
            leakInfo.push_back(info);
        } else {
            for (const auto &region : mapInfo) {
                if (value >= region.start && value <= region.end) {
                    info.bufIndex = i;
                    info.baseOffset = value - region.start;
                    info.leakType = getLeakType(region.image);
                    leakInfo.push_back(info);
                }
            }
        }
    }
    return leakInfo;
}

IOStates::LeakType IOStates::getLeakType(const std::string &image) const {
    if (image == g_crax->getExploit().getElfFilename()) {
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
