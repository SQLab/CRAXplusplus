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

#include <s2e/S2E.h>
#include <s2e/ConfigFile.h>
#include <s2e/Plugins/OSMonitors/Support/ProcessExecutionDetector.h>
#include <s2e/Plugins/OSMonitors/Support/MemoryMap.h>
#include <s2e/Plugins/CRAX/Utils/StringUtil.h>

#include "CRAX.h"

#define __CRAX_CONFIG_GET_T(Type, key, defaultValue) \
    (g_s2e->getConfig()->get##Type(getConfigKey() + key, defaultValue))

#define CRAX_CONFIG_GET_BOOL(key, defaultValue) \
    __CRAX_CONFIG_GET_T(Bool, key, defaultValue)

#define CRAX_CONFIG_GET_INT(key, defaultValue) \
    __CRAX_CONFIG_GET_T(Int, key, defaultValue)

#define CRAX_CONFIG_GET_STRING(key) \
    __CRAX_CONFIG_GET_T(String, key, "")

using namespace klee;


namespace s2e::plugins::crax {

CRAX *g_crax = nullptr;

S2E_DEFINE_PLUGIN(CRAX, "Modular Exploit Generation System", "", );

pybind11::scoped_interpreter CRAX::s_pybind11;
pybind11::module CRAX::s_pwnlib(pybind11::module::import("pwnlib.elf"));

CRAX::CRAX(S2E *s2e)
    : Plugin(s2e),
      beforeInstruction(),
      afterInstruction(),
      beforeSyscall(),
      afterSyscall(),
      onStateForkModuleDecide(),
      beforeExploitGeneration(),
      m_currentState(),
      m_linuxMonitor(),
      m_showInstructions(CRAX_CONFIG_GET_BOOL(".showInstructions", false)),
      m_showSyscalls(CRAX_CONFIG_GET_BOOL(".showSyscalls", true)),
      m_disableNativeForking(CRAX_CONFIG_GET_BOOL(".disableNativeForking", false)),
      m_userSpecifiedCanary(CRAX_CONFIG_GET_INT(".canary", 0)),
      m_userSpecifiedElfBase(CRAX_CONFIG_GET_INT(".elfBase", 0)),
      m_register(),
      m_memory(),
      m_disassembler(),
      m_exploit(CRAX_CONFIG_GET_STRING(".elfFilename"),
                CRAX_CONFIG_GET_STRING(".libcFilename")),
      m_exploitGenerator(),
      m_modules(),
      m_techniques(),
      m_targetProcessPid(),
      m_pendingOnExecuteSyscallEnd(),
      m_allowedForkingStates() {}


void CRAX::initialize() {
    g_crax = this;

    m_register.initialize();
    m_memory.initialize();

    m_linuxMonitor = s2e()->getPlugin<LinuxMonitor>();

    m_linuxMonitor->onProcessLoad.connect(
            sigc::mem_fun(*this, &CRAX::onProcessLoad));

    // Install symbolic RIP handler.
    s2e()->getCorePlugin()->onSymbolicAddress.connect(
            sigc::mem_fun(*this, &CRAX::onSymbolicRip));

    s2e()->getCorePlugin()->onStateForkDecide.connect(
            sigc::mem_fun(*this, &CRAX::onStateForkDecide));

    // Initialize modules.
    ConfigFile *cfg = s2e()->getConfig();
    ConfigFile::string_list moduleNames = cfg->getStringList(getConfigKey() + ".modules");

    foreach2 (it, moduleNames.begin(), moduleNames.end()) {
        log<INFO>() << "Creating module: " << *it << '\n';
        m_modules.push_back(Module::create(*it));
    }

    // Initialize techniques.
    ConfigFile::string_list techniqueNames = cfg->getStringList(getConfigKey() + ".techniques");

    foreach2 (it, techniqueNames.begin(), techniqueNames.end()) {
        log<INFO>() << "Creating technique: " << *it << '\n';
        m_techniques.push_back(Technique::create(*it));
    }
}


void CRAX::onSymbolicRip(S2EExecutionState *exploitableState,
                         ref<Expr> symbolicRip,
                         uint64_t concreteRip,
                         bool &concretize,
                         CorePlugin::symbolicAddressReason reason) {
    if (reason != CorePlugin::symbolicAddressReason::PC) {
        return;
    }

    // Set m_currentState to exploitableState.
    // All subsequent calls to reg() and mem() will operate on m_currentState.
    setCurrentState(exploitableState);

    log<WARN>()
        << "Detected symbolic RIP: " << hexval(concreteRip)
        << ", original value is: " << hexval(reg().readConcrete(Register::X64::RIP))
        << '\n';

    reg().setRipSymbolic(symbolicRip);

    // Dump CPU registers and virtual memory mappings.
    reg().showRegInfo();
    mem().showMapInfo();

    // Do whatever that needs to be done, and then generate the exploit.
    beforeExploitGeneration.emit();
    m_exploitGenerator.run();

    s2e()->getExecutor()->terminateState(*exploitableState, "End of exploit generation");
}

void CRAX::onProcessLoad(S2EExecutionState *state,
                         uint64_t cr3,
                         uint64_t pid,
                         const std::string &imageFileName) {
    setCurrentState(state);

    log<WARN>() << "onProcessLoad: " << imageFileName << '\n';

    if (imageFileName.find(m_exploit.getElfFilename()) != imageFileName.npos) {
        m_targetProcessPid = pid;

        m_linuxMonitor->onModuleLoad.connect(
                sigc::mem_fun(*this, &CRAX::onModuleLoad));

        s2e()->getCorePlugin()->onTranslateInstructionStart.connect(
                sigc::mem_fun(*this, &CRAX::onTranslateInstructionStart));

        s2e()->getCorePlugin()->onTranslateInstructionEnd.connect(
                sigc::mem_fun(*this, &CRAX::onTranslateInstructionEnd));
    }
}

void CRAX::onModuleLoad(S2EExecutionState *state,
                        const ModuleDescriptor &md) {
    setCurrentState(state);

    auto &os = log<WARN>();
    os << "onModuleLoad: " << md.Name << '\n';

    for (auto section : md.Sections) {
        section.name = md.Name;
        mem().getMappedSections().push_back(section);
    }

    // Resolve ELF base if the target binary has PIE.
    if (md.Name == "target" && m_exploit.getElf().getChecksec().hasPIE) {
        auto mapInfo = mem().getMapInfo();
        m_exploit.getElf().setBase(mapInfo.begin()->start);
        log<WARN>() << "ELF loaded at: " << hexval(mapInfo.begin()->start) << '\n';
    }
}

void CRAX::onTranslateInstructionStart(ExecutionSignal *onInstructionExecute,
                                       S2EExecutionState *state,
                                       TranslationBlock *tb,
                                       uint64_t pc) {
    if (m_linuxMonitor->isKernelAddress(pc)) {
        return;
    }

    // Register the instruction hook which will be called
    // before the instruction is executed.
    onInstructionExecute->connect(
            sigc::mem_fun(*this, &CRAX::onExecuteInstructionStart));
}

void CRAX::onTranslateInstructionEnd(ExecutionSignal *onInstructionExecute,
                                     S2EExecutionState *state,
                                     TranslationBlock *tb,
                                     uint64_t pc) {
    if (m_linuxMonitor->isKernelAddress(pc)) {
        return;
    }

    // Register the instruction hook which will be called
    // after the instruction is executed.
    onInstructionExecute->connect(
            sigc::mem_fun(*this, &CRAX::onExecuteInstructionEnd));
}

void CRAX::onExecuteInstructionStart(S2EExecutionState *state,
                                     uint64_t pc) {
    setCurrentState(state);

    std::optional<Instruction> i = m_disassembler.disasm(pc);

    if (!i) {
        return;
    }

    // XXX: m_pendingOnExecuteSyscallEnd should be state-specific?
    if (m_pendingOnExecuteSyscallEnd.size()) {
        auto it = m_pendingOnExecuteSyscallEnd.find(pc);
        if (it != m_pendingOnExecuteSyscallEnd.end()) {
            onExecuteSyscallEnd(state, pc, it->second);
        }
    }

    if (m_showInstructions && !m_linuxMonitor->isKernelAddress(pc)) {
        log<INFO>()
            << hexval(i->address) << ": "
            << i->mnemonic << ' ' << i->opStr
            << '\n';
    }

    if (i->mnemonic == "syscall") {
        onExecuteSyscallStart(state, pc);
    }

    // Execute instruction hooks installed by the user.
    beforeInstruction.emit(state, *i);
}

void CRAX::onExecuteInstructionEnd(S2EExecutionState *state,
                                   uint64_t pc) {
    setCurrentState(state);

    std::optional<Instruction> i = m_disassembler.disasm(pc);

    if (!i) {
        return;
    }

    // Execute instruction hooks installed by the user.
    afterInstruction.emit(state, *i);
}

void CRAX::onExecuteSyscallStart(S2EExecutionState *state,
                                 uint64_t pc) {
    SyscallCtx syscall;
    syscall.ret = 0;
    syscall.nr = reg().readConcrete(Register::X64::RAX);
    syscall.arg1 = reg().readConcrete(Register::X64::RDI);
    syscall.arg2 = reg().readConcrete(Register::X64::RSI);
    syscall.arg3 = reg().readConcrete(Register::X64::RDX);
    syscall.arg4 = reg().readConcrete(Register::X64::R10);
    syscall.arg5 = reg().readConcrete(Register::X64::R8);
    syscall.arg6 = reg().readConcrete(Register::X64::R9);

    if (m_showSyscalls) {
        log<INFO>()
            << "syscall: " << hexval(syscall.nr) << " ("
            << hexval(syscall.arg1) << ", "
            << hexval(syscall.arg2) << ", "
            << hexval(syscall.arg3) << ", "
            << hexval(syscall.arg4) << ", "
            << hexval(syscall.arg5) << ", "
            << hexval(syscall.arg6) << '\n';
    }

    // Schedule the syscall hook to be called
    // after the instruction at `pc + 2` is executed.
    // Note: pc == state->regs()->getPc().
    m_pendingOnExecuteSyscallEnd[pc + 2] = syscall;

    // Execute syscall hooks installed by the user.
    beforeSyscall.emit(state, m_pendingOnExecuteSyscallEnd[pc + 2]);
}

void CRAX::onExecuteSyscallEnd(S2EExecutionState *state,
                               uint64_t pc,
                               SyscallCtx &syscall) {
    // The kernel has finished serving the system call,
    // and the return value is now placed in RAX.
    syscall.ret = reg().readConcrete(Register::X64::RAX);

    // Execute syscall hooks installed by the user.
    afterSyscall.emit(state, syscall);
}

void CRAX::onStateForkDecide(S2EExecutionState *state,
                             const ref<Expr> &condition,
                             bool &allowForking) {
    // At this point, `*allowForking` is true by default.
    if (!m_disableNativeForking) {
        return;
    }

    // If the user has explicitly disabled all state forks done by S2E,
    // then we'll let CRAX's modules decide whether this fork should be done.
    onStateForkModuleDecide.emit(state, condition, allowForking);

    // We'll also check if current state forking was requested by CRAX.
    // If yes, then `state` should be in `m_allowedForkingStates`.
    allowForking |= m_allowedForkingStates.erase(state) == 1;
}


bool CRAX::isCallSiteOf(uint64_t instructionAddr,
                        const std::string &symbol) const {
    std::optional<Instruction> i = m_disassembler.disasm(instructionAddr);
    assert(i && "Unable to disassemble the instruction");

    if (i->mnemonic != "call") {
        return false;
    }

    const uint64_t symbolPlt = m_exploit.getElf().getRuntimeAddress(symbol);
    uint64_t operand = 0;
    try {
        operand = std::stoull(i->opStr, nullptr, 16);
    } catch (...) {
        // This can happen when `i` is something like `call r13`,
        // which is legit, so let's just silently swallow it...
    }
    return symbolPlt == operand;
}

std::string CRAX::getBelongingSymbol(uint64_t instructionAddr) const {
    ELF::SymbolMap __s = m_exploit.getElf().symbols();
    std::vector<std::pair<std::string, uint64_t>> syms(__s.begin(), __s.end());

    std::sort(syms.begin(),
              syms.end(),
              [](const auto &p1, const auto &p2) { return p1.second < p2.second; });

    if (instructionAddr < syms.front().second) {
        log<WARN>()
            << "Unable to find which symbol " << hexval(instructionAddr)
            << " belongs to.\n";
        return "";
    }

    // Use binary search to find out which symbol `instructionAddr` belongs to.
    int l = 0;
    int r = syms.size() - 1;

    while (l < r) {
        int m = l + (r - l) / 2;
        uint64_t addr = syms[m].second;
        if (addr < instructionAddr) {
            l = m + 1;
        } else {
            r = m - 1;
        }
    }

    if (instructionAddr < syms[l].second) {
        l--;
    }
    return syms[l].first;
}

}  // namespace s2e::plugins::crax
