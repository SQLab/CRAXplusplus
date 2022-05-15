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
#include <s2e/Plugins/CRAX/API/Disassembler.h>
#include <s2e/Plugins/CRAX/Modules/IOStates/LeakBasedCoreGenerator.h>
#include <s2e/Plugins/CRAX/Pwnlib/Util.h>
#include <s2e/Plugins/CRAX/Utils/VariantOverload.h>

#include <unistd.h>

#include "IOStates.h"

// XXX: define all syscall numbers
#define SYS_READ 0
#define SYS_WRITE 1
#define SYS_NANOSLEEP 35

using namespace klee;

namespace {

using __kernel_time64_t = long long;

struct __kernel_timespec {
    __kernel_time64_t tv_sec;  // seconds
    long long tv_nsec;         // nanoseconds
};

}  // namespace

namespace s2e::plugins::crax {

const std::array<std::string, IOStates::LeakType::LAST> IOStates::s_leakTypes = {{
    "unknown", "code", "libc", "heap", "stack", "canary"
}};


IOStates::IOStates()
    : Module(),
      m_leakTargets(),
      m_canary(),
      m_userSpecifiedCanary(g_s2e->getConfig()->getInt(getConfigKey() + ".canary", 0)),
      m_userSpecifiedElfBase(g_s2e->getConfig()->getInt(getConfigKey() + ".elfBase", 0)),
      m_userSpecifiedStateInfoList(initUserSpecifiedStateInfoList()) {
    const ELF &elf = g_crax->getExploit().getElf();

    // Install input state syscall hook.
    g_crax->beforeSyscall.connect(
            sigc::mem_fun(*this, &IOStates::inputStateHookTopHalf));

    g_crax->afterSyscall.connect(
            sigc::mem_fun(*this, &IOStates::inputStateHookBottomHalf));

    // Install output state syscall hook.
    g_crax->afterSyscall.connect(
            sigc::mem_fun(*this, &IOStates::outputStateHook));

    // Install sleep state syscall hook.
    g_crax->afterSyscall.connect(
            sigc::mem_fun(*this, &IOStates::sleepStateHook));

    g_crax->beforeExploitGeneration.connect(
            sigc::mem_fun(*this, &IOStates::beforeExploitGeneration));

    if (m_userSpecifiedCanary || m_userSpecifiedElfBase) {
        g_crax->setExploitForm(CRAX::ExploitForm::DATA);
    }

    // If either stack canary or PIE is enabled, then enable concolic mode
    // to avoid state explosion.
    if (elf.checksec.hasCanary || elf.checksec.hasPIE) {
        log<WARN>() << "IOStates loaded, forcing concolic mode.\n";
        g_crax->setConcolicMode(true);

        g_crax->onStateForkModuleDecide.connect(
                sigc::mem_fun(*this, &IOStates::onStateForkModuleDecide));
    }

    // Determine which base address(es) must be leaked
    // according to checksec of the target binary.
    if (elf.checksec.hasCanary) {
        g_crax->afterInstruction.connect(
                sigc::mem_fun(*this, &IOStates::maybeInterceptStackCanary));

        g_crax->beforeInstruction.connect(
                sigc::mem_fun(*this, &IOStates::onStackChkFailed));

        m_leakTargets.push_back(IOStates::LeakType::CANARY);
    }

    if (elf.checksec.hasPIE) {
        m_leakTargets.push_back(IOStates::LeakType::CODE);
    }
}

bool IOStates::checkRequirements() const {
    S2EExecutionState *state = g_crax->getCurrentState();

    auto modState = g_crax->getModuleState(state, this);
    modState->dump();

    if (hasLeakedAllRequiredInfo(state)) {
        return true;
    }

    log<WARN>()
        << "Some required information cannot be leaked, "
        << "skipping current state...\n";
    return false;
}

std::unique_ptr<CoreGenerator> IOStates::makeCoreGenerator() const {
    return std::make_unique<LeakBasedCoreGenerator>();
}


std::vector<IOStates::StateInfo> IOStates::initUserSpecifiedStateInfoList() {
    std::string str = g_s2e->getConfig()->getString(getConfigKey() + ".stateInfoList");

    if (str.empty()) {
        return {};
    }

    // Initialize user-specified state info list from the config.
    log<INFO>() << "User-specified StateInfoList: " << str << '\n';
    std::vector<StateInfo> ret;

    // Parse the string into state info list.
    for (const auto &s : split(str, ',')) {
        if (s[0] == 'i') {
            assert(s.size() > 1);
            InputStateInfo stateInfo;
            stateInfo.offset = std::stoull(s.substr(1));
            ret.push_back(std::move(stateInfo));

        } else if (s[0] == 'o') {
            OutputStateInfo stateInfo;
            stateInfo.isInteresting = false;
            if (s.size() > 1) {
                stateInfo.bufIndex = std::stoull(s.substr(1));
            }
            ret.push_back(std::move(stateInfo));

        } else if (s[0] == 's') {
            assert(s.size() > 1);
            SleepStateInfo stateInfo;
            stateInfo.sec = std::stoull(s.substr(1));
            ret.push_back(std::move(stateInfo));

        } else {
            pabort("Corrupted stateInfoList provided.");
        }
    }

    return ret;
}

void IOStates::inputStateHookTopHalf(S2EExecutionState *inputState,
                                     SyscallCtx &syscall) {
    if (syscall.nr != SYS_READ || syscall.arg1 != STDIN_FILENO) {
        return;
    }

    g_crax->setCurrentState(inputState);
    auto modState = g_crax->getModuleState(inputState, this);

    auto bufInfo = analyzeLeak(inputState, syscall.arg2, syscall.arg3);

    if (hasLeakedAllRequiredInfo(inputState)) {
        //log<WARN>() << "No more leak targets :^)\n";
        return;
    }

    auto &os = log<WARN>();
    os << " ---------- Analyzing input state ----------\n";
    for (size_t i = 0; i < bufInfo.size(); i++) {
        os << "[" << IOStates::s_leakTypes[i] << "]: ";
        for (uint64_t offset : bufInfo[i]) {
            os << hexval(offset) << ' ';
        }
        os << '\n';
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

        auto forkedModState = g_crax->getModuleState(forkedState, this);
        forkedModState->leakableOffset = offset;
    }
}

void IOStates::inputStateHookBottomHalf(S2EExecutionState *inputState,
                                        const SyscallCtx &syscall) {
    if (syscall.nr != SYS_READ || syscall.arg1 != STDIN_FILENO) {
        return;
    }

    g_crax->setCurrentState(inputState);

    auto modState = g_crax->getModuleState(inputState, this);

    InputStateInfo stateInfo;

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
    if (syscall.nr != SYS_WRITE || syscall.arg1 != STDOUT_FILENO) {
        return;
    }

    g_crax->setCurrentState(outputState);

    auto outputStateInfoList = detectLeak(outputState, syscall.arg2, syscall.arg3);
    auto modState = g_crax->getModuleState(outputState, this);

    // If the user has specified a state info list in s2e-config.lua,
    // then we should check if the leaked data's offset is really the same
    // as what user has claimed.
    if (m_userSpecifiedStateInfoList.size()) {
        size_t idx = modState->stateInfoList.size();
        assert(idx < m_userSpecifiedStateInfoList.size() &&
               "user-specified state info list out-of-bound...");

        OutputStateInfo stateInfo
            = std::get<OutputStateInfo>(m_userSpecifiedStateInfoList[idx]);

        if (stateInfo.isInteresting) {
            assert(stateInfo.bufIndex == outputStateInfoList.front().bufIndex &&
                   "OutputStateInfo bufIndex mismatch!?");
        }
    }

    OutputStateInfo stateInfo;
    stateInfo.isInteresting = false;

    if (outputStateInfoList.size() && !hasLeakedAllRequiredInfo(outputState)) {
        stateInfo.isInteresting = true;
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

void IOStates::sleepStateHook(S2EExecutionState *sleepState,
                              const SyscallCtx &syscall) {
    if (syscall.nr != SYS_NANOSLEEP) {
        return;
    }

    g_crax->setCurrentState(sleepState);

    auto modState = g_crax->getModuleState(sleepState, this);

    std::vector<uint8_t> bytes
        = mem().readConcrete(syscall.arg1, sizeof(__kernel_timespec));

    auto rqtp = reinterpret_cast<__kernel_timespec *>(bytes.data());

    log<WARN>() << "sys_nanosleep(): " << hexval(rqtp->tv_sec) << " secs\n";

    modState->stateInfoList.push_back(SleepStateInfo { rqtp->tv_sec });
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
        m_canary = reg().readConcrete(Register::X64::RAX);

        log<WARN>()
            << '[' << hexval(i.address) << "] "
            << "Intercepted canary: " << hexval(m_canary) << '\n';
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
    // If normal symbolic execution is used, then it will automatically fork
    // at canary-checking branches.
    if (!g_crax->isConcolicModeEnabled()) {
        return;
    }

    g_crax->setCurrentState(state);
    uint64_t rip = reg().readConcrete(Register::X64::RIP);

    // If the current branch instruction is the one before `call __stack_chk_fail@plt`,
    // then allow it to fork the current state.
    //
    // -> 401289:       74 05                   je     401290 <main+0xa2>
    //    40128b:       e8 20 fe ff ff          call   4010b0 <__stack_chk_fail@plt>
    //    401290:       c9                      leave
    std::optional<Instruction> i1 = disas().disasm(rip);  
    assert(i1 && "Disassemble failed? (i1)");

    std::optional<Instruction> i2 = disas().disasm(rip + i1->size);
    assert(i2 && "Disassemble failed? (i2)");

    // Look ahead the next instruction.
    if (!g_crax->isCallSiteOf(*i2, "__stack_chk_fail")) {
        allowForking = false;
        return;
    }

    log<WARN>() << "Allowing fork before __stack_chk_fail@plt\n";
    allowForking = true;

    if (m_userSpecifiedCanary) {
        log<WARN>()
            << "Constraining canary to " << hexval(m_userSpecifiedCanary)
            << " as requested.\n";

        // Hijack branch condition.
        assert(__condition);
        auto &condition = const_cast<ref<Expr> &>(__condition);

        uint64_t rbp = reg().readConcrete(Register::X64::RBP);
        condition = EqExpr::create(mem().readSymbolic(rbp - 8, Expr::Int64),
                                   ConstantExpr::create(m_userSpecifiedCanary, Expr::Int64));
    }
}

void IOStates::beforeExploitGeneration(S2EExecutionState *state) {
    auto modState = g_crax->getModuleState(state, this);

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
    const auto &vmmap = mem(inputState).vmmap();
    std::array<std::vector<uint64_t>, IOStates::LeakType::LAST> bufInfo;

    for (uint64_t i = 0; i < len; i += 8) {
        uint64_t value = u64(mem().readConcrete(buf + i, 8, /*concretize=*/false));
        //log<WARN>() << "addr = " << hexval(buf + i) << " value = " << hexval(value) << '\n';

        if (g_crax->getExploit().getElf().checksec.hasCanary && value == m_canary) {
            bufInfo[LeakType::CANARY].push_back(i);
        } else {
            foreach2 (it, vmmap.begin(), vmmap.end()) {
                if (value >= it.start() && value <= it.stop()) {
                    RegionDescriptorPtr region = *it;
                    bufInfo[getLeakType(region->moduleName)].push_back(i);
                }
            }
        }
    }
    return bufInfo;
}

std::vector<IOStates::OutputStateInfo>
IOStates::detectLeak(S2EExecutionState *outputState, uint64_t buf, uint64_t len) {
    const auto &vmmap = mem(outputState).vmmap();
    std::vector<IOStates::OutputStateInfo> leakInfo;

    IOStates::OutputStateInfo info;
    info.isInteresting = true;

    for (uint64_t i = 0; i < len; i++) {
        uint64_t n = std::min(len - i, static_cast<uint64_t>(8));
        uint64_t value = u64(mem().readConcrete(buf + i, n, /*concretize=*/false));
        //log<WARN>() << "addr = " << hexval(buf + i) << " value = " << hexval(value) << '\n';

        if (g_crax->getExploit().getElf().checksec.hasCanary && (value & ~0xff) == m_canary) {
            info.bufIndex = i + 1;
            info.baseOffset = 0;
            info.leakType = LeakType::CANARY;
            leakInfo.push_back(info);
        } else {
            value &= 0xffff'ffff'ffff;
            foreach2 (it, vmmap.begin(), vmmap.end()) {
                if (value >= it.start() && value <= it.stop()) {
                    RegionDescriptorPtr region = *it;
                    info.bufIndex = i;
                    info.baseOffset = value - vmmap.getModuleBaseAddress(value);
                    info.leakType = getLeakType(region->moduleName);
                    leakInfo.push_back(info);
                }
            }
        }
    }
    return leakInfo;
}

bool IOStates::hasLeakedAllRequiredInfo(S2EExecutionState *state) const {
    auto modState = g_crax->getModuleState(state, this);
    return modState->currentLeakTargetIdx >= m_leakTargets.size();
}

IOStates::LeakType IOStates::getLeakType(const std::string &image) const {
    if (image == VirtualMemoryMap::s_elfLabel) {
        return IOStates::LeakType::CODE;
    } else if (image == VirtualMemoryMap::s_libcLabel) {
        return IOStates::LeakType::LIBC;
    } else if (image == VirtualMemoryMap::s_stackLabel) {
        return IOStates::LeakType::STACK;
    } else {
        return IOStates::LeakType::UNKNOWN;
    }
}


void IOStates::State::dump() const {
    auto &os = log<WARN>();
    os << "Dumping IOStates: [";
    os << toString();
    os << "]\n";
}

std::string IOStates::State::toString() const {
    std::string ret;

    for (size_t i = 0; i < stateInfoList.size(); i++) {
        std::visit(overload {
            [&ret](const InputStateInfo &stateInfo) {
                ret += 'i' + std::to_string(stateInfo.offset);
            },
            [&ret](const OutputStateInfo &stateInfo) {
                ret += 'o';
                if (stateInfo.isInteresting) {
                    ret += std::to_string(stateInfo.bufIndex);
                }
            },
            [&ret](const SleepStateInfo &stateInfo) {
                ret += 's' + std::to_string(stateInfo.sec);
            }
        }, stateInfoList[i]);

        if (i != stateInfoList.size() - 1) {
            ret += ',';
        }
    }
    return ret;
}

}  // namespace s2e::plugins::crax
