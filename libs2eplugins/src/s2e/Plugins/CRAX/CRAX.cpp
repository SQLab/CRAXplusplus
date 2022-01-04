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
#include <s2e/Plugins/CRAX/Modules/RopChainBuilder.h>
#include <s2e/Plugins/CRAX/Utils/StringUtil.h>

#include <fstream>
#include <string>
#include <vector>
#include <memory>

#include "CRAX.h"

using namespace klee;

namespace s2e::plugins::crax {

S2E_DEFINE_PLUGIN(CRAX, "Modular Exploit Generation System", "", );

pybind11::scoped_interpreter CRAX::s_pybind11;
pybind11::module CRAX::s_pwnlib(pybind11::module::import("pwnlib.elf"));


CRAX::CRAX(S2E *s2e)
    : Plugin(s2e),
      beforeInstructionHooks(),
      afterInstructionHooks(),
      beforeSyscallHooks(),
      afterSyscallHooks(),
      exploitGenerationHooks(),
      m_currentState(),
      m_linuxMonitor(),
      m_register(*this),
      m_memory(*this),
      m_disassembler(*this),
      m_exploit(g_s2e->getConfig()->getString(getConfigKey() + ".elfFilename"),
                g_s2e->getConfig()->getString(getConfigKey() + ".libcFilename")),
      m_targetProcessPid(),
      m_modules(),
      m_readPrimitives(),
      m_writePrimitives() {}


void CRAX::initialize() {
    // Initialize CRAX++'s logging module.
    initCRAXLogging(this);
    m_register.initialize();
    m_memory.initialize();

    m_linuxMonitor = s2e()->getPlugin<LinuxMonitor>();

    m_linuxMonitor->onProcessLoad.connect(
            sigc::mem_fun(*this, &CRAX::onProcessLoad));

    // Install symbolic RIP handler.
    s2e()->getCorePlugin()->onSymbolicAddress.connect(
            sigc::mem_fun(*this, &CRAX::onSymbolicRip));

    // Initialize modules.
    ConfigFile *cfg = s2e()->getConfig();
    ConfigFile::string_list moduleNames = cfg->getStringList(getConfigKey() + ".modules");
    foreach2 (it, moduleNames.begin(), moduleNames.end()) {
        log<WARN>() << "initializing: " << *it << '\n';
        m_modules.push_back(Module::create(*this, *it));
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
        << "\n";

    reg().setRipSymbolic(symbolicRip);

    // Dump CPU registers.
    reg().showRegInfo();

    // Dump virtual memory mappings.
    mem().showMapInfo(m_targetProcessPid);

    // Execute exploit generation hooks installed by the user.
    exploitGenerationHooks.emit();

    s2e()->getExecutor()->terminateState(*exploitableState, "End of exploit generation");
}

void CRAX::onProcessLoad(S2EExecutionState *state,
                         uint64_t cr3,
                         uint64_t pid,
                         const std::string &imageFileName) {
    setCurrentState(state);

    log<WARN>() << "onProcessLoad: " << imageFileName << "\n";

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
}

void CRAX::onTranslateInstructionStart(ExecutionSignal *onInstructionExecute,
                                       S2EExecutionState *state,
                                       TranslationBlock *tb,
                                       uint64_t pc) {
    if (!m_linuxMonitor->isKernelAddress(pc)) {
        // Register the instruction hook which
        // will be called before the instruction is executed.
        onInstructionExecute->connect(
                sigc::mem_fun(*this, &CRAX::onExecuteInstructionStart));
    }
}

void CRAX::onTranslateInstructionEnd(ExecutionSignal *onInstructionExecute,
                                     S2EExecutionState *state,
                                     TranslationBlock *tb,
                                     uint64_t pc) {
    if (!m_linuxMonitor->isKernelAddress(pc)) {
        // Register the instruction hook which
        // will be called after the instruction is executed.
        onInstructionExecute->connect(
                sigc::mem_fun(*this, &CRAX::onExecuteInstructionEnd));
    }
}

void CRAX::onExecuteInstructionStart(S2EExecutionState *state,
                                     uint64_t pc) {
    setCurrentState(state);

    std::optional<Instruction> i = m_disassembler.disasm(pc);

    if (!i) {
        return;
    }

    if (i->mnemonic == "syscall") {
        onExecuteSyscallStart(state);
    }

    // Execute instruction hooks installed by the user.
    beforeInstructionHooks.emit(state, *i);
}

void CRAX::onExecuteInstructionEnd(S2EExecutionState *state,
                                   uint64_t pc) {
    setCurrentState(state);

    std::optional<Instruction> i = m_disassembler.disasm(pc);

    if (!i) {
        return;
    }

    if (s2e()->getConfig()->getBool(getConfigKey() + ".showInstructions", false) &&
        !m_linuxMonitor->isKernelAddress(pc)) {
        log<INFO>()
            << hexval(i->address) << ": " << i->mnemonic << ' ' << i->opStr << '\n';
    }

    if (i->mnemonic == "syscall") {
        onExecuteSyscallEnd(state);
    }

    // Execute instruction hooks installed by the user.
    afterInstructionHooks.emit(state, *i);
}

void CRAX::onExecuteSyscallStart(S2EExecutionState *state) {
    uint64_t rax = reg().readConcrete(Register::X64::RAX);
    uint64_t rdi = reg().readConcrete(Register::X64::RDI);
    uint64_t rsi = reg().readConcrete(Register::X64::RSI);
    uint64_t rdx = reg().readConcrete(Register::X64::RDX);
    uint64_t r10 = reg().readConcrete(Register::X64::R10);
    uint64_t r8  = reg().readConcrete(Register::X64::R8);
    uint64_t r9  = reg().readConcrete(Register::X64::R9);

    // Execute syscall hooks installed by the user.
    beforeSyscallHooks.emit(state, rax, rdi, rsi, rdx, r10, r8, r9);
}

void CRAX::onExecuteSyscallEnd(S2EExecutionState *state) {
    uint64_t rax = reg().readConcrete(Register::X64::RAX);
    uint64_t rdi = reg().readConcrete(Register::X64::RDI);
    uint64_t rsi = reg().readConcrete(Register::X64::RSI);
    uint64_t rdx = reg().readConcrete(Register::X64::RDX);
    uint64_t r10 = reg().readConcrete(Register::X64::R10);
    uint64_t r8  = reg().readConcrete(Register::X64::R8);
    uint64_t r9  = reg().readConcrete(Register::X64::R9);

    if (s2e()->getConfig()->getBool(getConfigKey() + ".showSyscalls", true)) {
        log<INFO>()
            << "syscall: " << hexval(rax) << " ("
            << hexval(rdi) << ", "
            << hexval(rsi) << ", "
            << hexval(rdx) << ", "
            << hexval(r10) << ", "
            << hexval(r8) << ", "
            << hexval(r9) << '\n';
    }

    // Execute syscall hooks installed by the user.
    afterSyscallHooks.emit(state, rax, rdi, rsi, rdx, r10, r8, r9);
}

}  // namespace s2e::plugins::crax
