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

#include "Requiem.h"

#include <string>

#include <cpu/i386/cpu.h>
#include <s2e/S2E.h>
#include <s2e/ConfigFile.h>
#include <s2e/Plugins/OSMonitors/Support/ProcessExecutionDetector.h>
#include <s2e/Plugins/OSMonitors/Support/MemoryMap.h>
#include <s2e/Plugins/Requiem/Pwnlib/ELF.h>

using namespace klee;
namespace py = pybind11;

namespace s2e::plugins::requiem {

using Register = RegisterManager::Register;

S2E_DEFINE_PLUGIN(Requiem, "Automatic Exploit Generation Engine", "", );


Requiem::Requiem(S2E *s2e)
    : Plugin(s2e),
      m_linuxMonitor(),
      m_pybind11(),
      m_pwnlib(py::module::import("pwnlib.elf")),
      m_registerManager(),
      m_memoryManager(),
      m_disassembler(*this),
      m_exploit(m_pwnlib,
                g_s2e->getConfig()->getString(getConfigKey() + ".elfFilename"),
                g_s2e->getConfig()->getString(getConfigKey() + ".libcFilename")),
      m_target_process_pid() {}


void Requiem::initialize() {
    m_linuxMonitor = g_s2e->getPlugin<LinuxMonitor>();

    m_registerManager.initialize();
    m_memoryManager.initialize();

    m_linuxMonitor->onProcessLoad.connect(
            sigc::mem_fun(*this, &Requiem::onProcessLoad));

    g_s2e->getCorePlugin()->onSymbolicAddress.connect(
            sigc::mem_fun(*this, &Requiem::onRipCorrupt));
}


void Requiem::onRipCorrupt(S2EExecutionState *state,
                           klee::ref<klee::Expr> virtualAddress,
                           uint64_t concreteAddress,
                           bool &concretize,
                           CorePlugin::symbolicAddressReason reason) {
    if (reason != CorePlugin::symbolicAddressReason::PC) {
        return;
    }

    auto &os = g_s2e->getWarningsStream(state);

    os << "Detected symbolic RIP: " << klee::hexval(concreteAddress)
        << ", original value is: " << klee::hexval(state->regs()->getPc())
        << "\n";

    reg().setRipSymbolic(virtualAddress);

    // Dump CPU registers.
    reg().showRegInfo(state);

    // Dump virtual memory mappings.
    mem().showMapInfo(state, m_target_process_pid);

    // Disassembler test.
    os << "main = " << hexval(m_exploit.getElf().symbols()["main"]) << "\n";

    for (auto insn : m_disassembler.disasm(state, "main")) {
        os << hexval(insn.address) << ": " << insn.mnemonic << " " << insn.op_str << "\n";
    }

    g_s2e->getExecutor()->terminateState(*state, "End of exploit generation");
}

void Requiem::onProcessLoad(S2EExecutionState *state,
                            uint64_t cr3,
                            uint64_t pid,
                            const std::string &imageFileName) {
    g_s2e->getWarningsStream(state) << "onProcessLoad: " << imageFileName << "\n";

    if (imageFileName.find(m_exploit.getElfFilename()) != imageFileName.npos) {
        m_target_process_pid = pid;

        g_s2e->getCorePlugin()->onTranslateInstructionEnd.connect(
                sigc::mem_fun(*this, &Requiem::onTranslateInstructionEnd));
    }
}

void Requiem::onTranslateInstructionEnd(ExecutionSignal *onInstructionExecute,
                                        S2EExecutionState *state,
                                        TranslationBlock *tb,
                                        uint64_t pc) {
    if (pc == m_exploit.getElf().symbols()["main"]) {
        g_s2e->getWarningsStream(state) << "reached main()\n";
    }

    if (m_linuxMonitor->isKernelAddress(pc)) {
        return;
    }

    onInstructionExecute->connect(
            sigc::mem_fun(*this, & Requiem::instructionHook));
}

void Requiem::instructionHook(S2EExecutionState *state, uint64_t pc) {
    Instruction i = m_disassembler.disasm(state, pc);

    /*
    if (pc <= 0x500000) {
        g_s2e->getInfoStream()
            << klee::hexval(i.address) << ": " << i.mnemonic << " " << i.op_str << "\n";
    }
    */

    if (i.mnemonic == "syscall") {
        syscallHook(state, pc);
    }
}

void Requiem::syscallHook(S2EExecutionState *state, uint64_t pc) {
    g_s2e->getInfoStream(state)
        << "syscall: " << hexval(reg().readConcrete(state, Register::RAX)) << " ("
        << hexval(reg().readConcrete(state, Register::RDI)) << ", "
        << hexval(reg().readConcrete(state, Register::RSI)) << ", "
        << hexval(reg().readConcrete(state, Register::RDX)) << ", "
        << hexval(reg().readConcrete(state, Register::R10)) << ", "
        << hexval(reg().readConcrete(state, Register::R8)) << ", "
        << hexval(reg().readConcrete(state, Register::R9)) << ")\n";
}


void Requiem::handleOpcodeInvocation(S2EExecutionState *state,
                                     uint64_t guestDataPtr,
                                     uint64_t guestDataSize) {
    S2E_REQUIEM_COMMAND command;

    if (guestDataSize != sizeof(command)) {
        getWarningsStream(state) << "mismatched S2E_REQUIEM_COMMAND size\n";
        return;
    }

    if (!state->mem()->read(guestDataPtr, &command, guestDataSize)) {
        getWarningsStream(state) << "could not read transmitted data\n";
        return;
    }

    switch (command.Command) {
        // TODO: add custom commands here
        case COMMAND_1:
            break;
        default:
            getWarningsStream(state) << "Unknown command " << command.Command << "\n";
            break;
    }
}

}  // namespace s2e::plugins::requiem
