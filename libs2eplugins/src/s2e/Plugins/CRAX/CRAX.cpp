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
#include <s2e/Plugins/CRAX/Strategies/DefaultStrategy.h>
#include <s2e/Plugins/CRAX/Utils/StringUtil.h>

#include <fstream>
#include <string>
#include <vector>
#include <memory>

#include "CRAX.h"

using namespace klee;

namespace s2e::plugins::crax {

S2E_DEFINE_PLUGIN(CRAX, "Automatic Exploit Generation Engine", "", );


CRAX::CRAX(S2E *s2e)
    : Plugin(s2e),
      instructionHooks(),
      syscallHooks(),
      m_linuxMonitor(),
      m_pybind11(),
      m_pwnlib(pybind11::module::import("pwnlib.elf")),
      m_registerManager(*this),
      m_memoryManager(*this),
      m_exploit(*this,
                g_s2e->getConfig()->getString(getConfigKey() + ".elfFilename"),
                g_s2e->getConfig()->getString(getConfigKey() + ".libcFilename")),
      m_disassembler(*this),
      m_ropChainBuilder(*this),
      m_targetProcessPid(),
      m_strategy(),
      m_ioBehaviors(),
      m_readPrimitives(),
      m_writePrimitives() {}


void CRAX::initialize() {
    m_linuxMonitor = s2e()->getPlugin<LinuxMonitor>();

    m_registerManager.initialize();
    m_memoryManager.initialize();

    m_linuxMonitor->onProcessLoad.connect(
            sigc::mem_fun(*this, &CRAX::onProcessLoad));

    s2e()->getCorePlugin()->onSymbolicAddress.connect(
            sigc::mem_fun(*this, &CRAX::onSymbolicRip));
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
        << ", original value is: " << hexval(reg().readConcrete(Register::RIP))
        << "\n";

    reg().setRipSymbolic(symbolicRip);

    // Dump CPU registers.
    reg().showRegInfo();

    // Dump virtual memory mappings.
    mem().showMapInfo(m_targetProcessPid);

    if (!generateExploit()) {
        log<WARN>() << "Failed to generate exploit.\n";
    }

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

        s2e()->getCorePlugin()->onTranslateInstructionEnd.connect(
                sigc::mem_fun(*this, &CRAX::onTranslateInstructionEnd));
    }
}

void CRAX::onTranslateInstructionEnd(ExecutionSignal *onInstructionExecute,
                                        S2EExecutionState *state,
                                        TranslationBlock *tb,
                                        uint64_t pc) {
    setCurrentState(state);

    if (!m_linuxMonitor->isKernelAddress(pc)) {
        // Register instruction hook.
        onInstructionExecute->connect(
                sigc::mem_fun(*this, &CRAX::onExecuteInstructionEnd));
    }
}

void CRAX::onExecuteInstructionEnd(S2EExecutionState *state,
                                      uint64_t pc) {
    setCurrentState(state);

    Instruction i = m_disassembler.disasm(pc);

    if (s2e()->getConfig()->getBool(getConfigKey() + ".showInstructions", false) &&
        !m_linuxMonitor->isKernelAddress(pc)) {
        log<INFO>() << hexval(i.address) << ": " << i.mnemonic << ' ' << i.opStr << '\n';
    }

    if (i.mnemonic == "syscall") {
        onExecuteSyscallEnd(state, pc);
    }

    // Execute instruction hooks installed by the user.
    instructionHooks.emit(state, i);
}

void CRAX::onExecuteSyscallEnd(S2EExecutionState *state,
                                  uint64_t pc) {
    setCurrentState(state);

    uint64_t rax = reg().readConcrete(Register::RAX);
    uint64_t rdi = reg().readConcrete(Register::RDI);
    uint64_t rsi = reg().readConcrete(Register::RSI);
    uint64_t rdx = reg().readConcrete(Register::RDX);
    uint64_t r10 = reg().readConcrete(Register::R10);
    uint64_t r8  = reg().readConcrete(Register::R8);
    uint64_t r9  = reg().readConcrete(Register::R9);

    if (s2e()->getConfig()->getBool(getConfigKey() + ".showSyscalls", true)) {
        log<INFO>()
            << "syscall: " << hexval(rax) << " ("
            << hexval(rdi) << ", "
            << hexval(rsi) << ", "
            << hexval(rdx) << ", "
            << hexval(r10) << ", "
            << hexval(r8) << ", "
            << hexval(r9) << ")\n";
    }

    // Execute syscall hooks installed by the user.
    syscallHooks.emit(state, rax, rdi, rsi, rdx, r10, r8, r9);
}

bool CRAX::generateExploit() {
    // Write exploit shebang.
    m_exploit.writeline(Exploit::s_shebang);

    // Pwntools stuff.
    m_exploit.writelines({
        "from pwn import *",
        "context.update(arch = 'amd64', os = 'linux', log_level = 'info')",
        "",
        format("elf = ELF('%s', checksec=False)", m_exploit.getElfFilename().c_str()),
    });

    // Determine exploit strategy.
    if (!m_strategy) {
        m_strategy = std::make_unique<DefaultStrategy>(*this);
    }

    // Check requirements.
    std::vector<Technique *> primaryTechniques = m_strategy->getPrimaryTechniques();

    for (auto t : primaryTechniques) {
        if (!t->checkRequirements()) {
            log<WARN>() << "Requirements unsatisfied: " << t->toString() << '\n';
            return false;
        }
    }

    m_exploit.registerSymbol("elf_base", 0);

    // Declare symbols and values.
    for (const auto &entry : m_exploit.getSymtab()) {
        const auto &name = entry.first;
        const auto &value = entry.second;
        m_exploit.writeline(format("%s = 0x%llx", name.c_str(), value));
    }

    m_exploit.writeline();

    // Write exploit body.
    m_exploit.writelines({
        "if __name__ == '__main__':",
        "    proc = elf.process()",
    });

    // Build ROP chain based on the strategy list chosen by the user.
    if (!m_ropChainBuilder.build(m_exploit, primaryTechniques)) {
        return false;
    }

    // Write exploit trailer.
    m_exploit.writeline("    proc.interactive()");

    // Write the buffered content to the file.
    std::ofstream ofs(m_exploit.getFilename());
    ofs << m_exploit.getContent();

    log<WARN>() << "Generated exploit script: " << m_exploit.getFilename() << "\n";
    return true;
}

}  // namespace s2e::plugins::crax
