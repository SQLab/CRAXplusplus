// Copyright (C) 2021-2022, Marco Wang
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

#include <cpu/i386/cpu.h>
#include <s2e/S2E.h>
#include <s2e/ConfigFile.h>
#include <s2e/Plugins/OSMonitors/Support/ProcessExecutionDetector.h>
#include <s2e/Plugins/OSMonitors/Support/MemoryMap.h>
#include <s2e/Plugins/Requiem/Expr/BinaryExprEvaluator.h>
#include <s2e/Plugins/Requiem/Strategies/DefaultStrategy.h>
#include <s2e/Plugins/Requiem/Techniques/StackPivot.h>
#include <s2e/Plugins/Requiem/Utils/StringUtil.h>

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <memory>

#include "Requiem.h"

using namespace klee;
namespace py = pybind11;

namespace s2e::plugins::requiem {

using SymbolicRopPayload = Technique::SymbolicRopPayload;
using ConcreteRopPayload = Technique::ConcreteRopPayload;

S2E_DEFINE_PLUGIN(Requiem, "Automatic Exploit Generation Engine", "", );


Requiem::Requiem(S2E *s2e)
    : Plugin(s2e),
      m_linuxMonitor(),
      m_pybind11(),
      m_pwnlib(py::module::import("pwnlib.elf")),
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
      m_writePrimitives(),
      m_inputState(),
      m_padding(),
      m_sysReadBuf(),
      m_sysReadSize() {}


void Requiem::initialize() {
    m_linuxMonitor = g_s2e->getPlugin<LinuxMonitor>();

    m_registerManager.initialize();
    m_memoryManager.initialize();

    m_linuxMonitor->onProcessLoad.connect(
            sigc::mem_fun(*this, &Requiem::onProcessLoad));

    g_s2e->getCorePlugin()->onSymbolicAddress.connect(
            sigc::mem_fun(*this, &Requiem::onSymbolicRip));
}


void Requiem::onSymbolicRip(S2EExecutionState *exploitableState,
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

    // Calculate padding from user input's base addr to saved rbp.
    // XXX: use symbolic execution instead.
    m_padding = reg().readConcrete(Register::RSP) - m_sysReadBuf - 16;

    if (!generateExploit()) {
        log<WARN>() << "Failed to generate exploit.\n";
    }

    g_s2e->getExecutor()->terminateState(*exploitableState, "End of exploit generation");
}

void Requiem::onProcessLoad(S2EExecutionState *state,
                            uint64_t cr3,
                            uint64_t pid,
                            const std::string &imageFileName) {
    setCurrentState(state);

    log<WARN>() << "onProcessLoad: " << imageFileName << "\n";

    if (imageFileName.find(m_exploit.getElfFilename()) != imageFileName.npos) {
        m_targetProcessPid = pid;

        g_s2e->getCorePlugin()->onTranslateInstructionEnd.connect(
                sigc::mem_fun(*this, &Requiem::onTranslateInstructionEnd));
    }
}

void Requiem::onTranslateInstructionEnd(ExecutionSignal *onInstructionExecute,
                                        S2EExecutionState *state,
                                        TranslationBlock *tb,
                                        uint64_t pc) {
    setCurrentState(state);

    if (pc == m_exploit.getElf().symbols()["main"]) {
        log<WARN>() << "reached main()\n";
    }

    if (m_linuxMonitor->isKernelAddress(pc)) {
        return;
    }

    onInstructionExecute->connect(
            sigc::mem_fun(*this, &Requiem::onExecuteInstructionEnd));
}

void Requiem::onExecuteInstructionEnd(S2EExecutionState *state,
                                      uint64_t pc) {
    setCurrentState(state);

    Instruction i = m_disassembler.disasm(pc);

    /*
    if (pc <= 0x500000) {
        g_s2e->getInfoStream()
            << hexval(i.address) << ": " << i.mnemonic << " " << i.op_str << "\n";
    }
    */

    if (i.mnemonic == "syscall") {
        onExecuteSyscallEnd(state, pc);
    }

    static auto isCallSiteOf = [this](const std::string &opStr,
                                      const std::string &funcName) {
        const auto &sym = m_exploit.getElf().symbols();
        auto it = sym.find(funcName);
        return it != sym.end() && std::stoull(opStr, nullptr, 16) == it->second;
    };

    if (pc <= 0x500000 && i.mnemonic == "call" && i.op_str.find("0x") == 0) {
        log<WARN>() << i.mnemonic << " " << i.op_str << "\n";

        if (isCallSiteOf(i.op_str, "read")) {
            log<WARN>() << "discovered a call site of read@libc.\n";
            m_ioBehaviors.push_back(std::make_unique<InputBehavior>());
            m_writePrimitives.push_back(i.address);
        } else if (isCallSiteOf(i.op_str, "sleep")) {
            log<WARN>() << "discovered a call site of sleep@libc.\n";
            uint64_t interval = reg().readConcrete(Register::RDI);
            m_ioBehaviors.push_back(std::make_unique<SleepBehavior>(interval));
        }
    }
}

void Requiem::onExecuteSyscallEnd(S2EExecutionState *state,
                                  uint64_t pc) {
    setCurrentState(state);

    log<INFO>()
        << "syscall: " << hexval(reg().readConcrete(Register::RAX)) << " ("
        << hexval(reg().readConcrete(Register::RDI)) << ", "
        << hexval(reg().readConcrete(Register::RSI)) << ", "
        << hexval(reg().readConcrete(Register::RDX)) << ", "
        << hexval(reg().readConcrete(Register::R10)) << ", "
        << hexval(reg().readConcrete(Register::R8)) << ", "
        << hexval(reg().readConcrete(Register::R9)) << ")\n";

    // sys_read from stdin?
    if (reg().readConcrete(Register::RAX) == 0 &&
        reg().readConcrete(Register::RDI) == 0) {
        m_sysReadBuf = reg().readConcrete(Register::RSI);
        m_sysReadSize = reg().readConcrete(Register::RDX);

        /*
        // Create input state snapshot.
        if (state->needToJumpToSymbolic()) {
            state->regs()->setPc(pc);
            state->jumpToSymbolic();
        }
        S2EExecutor::StatePair sp = g_s2e->getExecutor()->fork(*state);
        m_inputState = dynamic_cast<S2EExecutionState *>(sp.second);
        */
    } else if (reg().readConcrete(Register::RAX) == 1 &&
               reg().readConcrete(Register::RDI) == 1) {
        log<WARN>() << "sys_write()\n";
        // Create output state snapshot.
    }
}

bool Requiem::generateExploit() {
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

    for (Technique *t : primaryTechniques) {
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

    // I/O Behaviors.
    for (const auto &b : m_ioBehaviors) {
        Behavior *behavior = b.get();
        if (auto sb = dynamic_cast<SleepBehavior *>(behavior)) {
            m_exploit.writeline(format("    time.sleep(%d)", sb->getInterval()));
        }
    }

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

}  // namespace s2e::plugins::requiem
