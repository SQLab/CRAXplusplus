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

#include <s2e/S2E.h>
#include <s2e/ConfigFile.h>
#include <s2e/Plugins/Requiem/Pwnlib/ELF.h>

namespace py = pybind11;

namespace s2e::plugins::requiem {

namespace {

// This class can optionally be used to store per-state plugin data.
//
// Use it as follows:
// void ExploitGenerator::onEvent(S2EExecutionState *state, ...) {
//     DECLARE_PLUGINSTATE(RequiemState, state);
//     plgState->...
// }

class RequiemState: public PluginState {
    // Declare any methods and fields you need here

public:
    static PluginState *factory(Plugin *p, S2EExecutionState *s) {
        return new RequiemState();
    }

    virtual ~RequiemState() {
        // Destroy any object if needed
    }

    virtual RequiemState *clone() const {
        return new RequiemState(*this);
    }
};

}  // namespace


S2E_DEFINE_PLUGIN(Requiem, "Automatic Exploit Generation Engine", "", );


Requiem::Requiem(S2E *s2e)
    : Plugin(s2e),
      m_pybind11(),
      m_pwnlib(py::module::import("pwnlib.elf")),
      m_monitor(),
      m_disassembler(*this),
      m_exploit(m_pwnlib,
                g_s2e->getConfig()->getString(getConfigKey() + ".elfFilename"),
                g_s2e->getConfig()->getString(getConfigKey() + ".libcFilename")),
      m_target_process_pid() {}


void Requiem::initialize() {
    m_monitor = static_cast<LinuxMonitor *>(g_s2e->getPlugin("OSMonitor"));

    m_monitor->onProcessLoad.connect(
            sigc::mem_fun(*this, &Requiem::onProcessLoad));

    m_monitor->onMemoryMap.connect(
            sigc::mem_fun(*this, &Requiem::onMemoryMap));

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

    g_s2e->getWarningsStream(state)
        << "Detected symbolic RIP: " << klee::hexval(concreteAddress)
        << ", original value is: " << klee::hexval(state->regs()->getPc()) << "\n";

    g_s2e->getExecutor()->terminateState(*state, "End of exploit generation");
}

void Requiem::onProcessLoad(S2EExecutionState *state,
                            uint64_t cr3,
                            uint64_t pid,
                            const std::string &imageFileName) {
    if (imageFileName.find(m_exploit.getElfFilename()) != imageFileName.npos) {
        m_target_process_pid = pid;

        g_s2e->getCorePlugin()->onTranslateInstructionEnd.connect(
                sigc::mem_fun(*this, &Requiem::onTranslateInstructionEnd));
    }
}

void Requiem::onMemoryMap(S2EExecutionState *state,
                          uint64_t pid,
                          uint64_t start,
                          uint64_t size,
                          uint64_t prot) {
    // Is the target process running?
    if (m_target_process_pid && m_target_process_pid == pid) {
        g_s2e->getInfoStream()
            << "section: " << klee::hexval(start) << " "
            << klee::hexval(size) << "\n";
    }
}

void Requiem::onTranslateInstructionEnd(ExecutionSignal *onInstructionExecute,
                                        S2EExecutionState *state,
                                        TranslationBlock *tb,
                                        uint64_t pc) {
    if (pc == m_exploit.getElf().symbols()["main"]) {
        g_s2e->getWarningsStream(state) << "reached main()\n";
    }

    if (pc >= m_monitor->getKernelStart()) {
        return;
    }

    onInstructionExecute->connect(
            sigc::mem_fun(*this, & Requiem::instructionHook));
}

void Requiem::instructionHook(S2EExecutionState *state,
                              uint64_t pc) {
    Instruction i = m_disassembler.disasm(state, pc);

    //if (pc <= 0x500000) {
    //    g_s2e->getInfoStream() << klee::hexval(i.address) << ": " << i.mnemonic << " " << i.op_str << "\n";
    //}

    if (i.mnemonic == "syscall") {
        syscallHook(state, pc);
    }
}

void Requiem::syscallHook(S2EExecutionState *state,
                          uint64_t pc) {
    uint64_t rax = state->regs()->read<uint64_t>(CPU_OFFSET(regs[R_EAX]));
    uint64_t rdi = state->regs()->read<uint64_t>(CPU_OFFSET(regs[R_EDI]));
    uint64_t rsi = state->regs()->read<uint64_t>(CPU_OFFSET(regs[R_ESI]));
    uint64_t rdx = state->regs()->read<uint64_t>(CPU_OFFSET(regs[R_EDX]));
    uint64_t r10 = state->regs()->read<uint64_t>(CPU_OFFSET(regs[10]));
    uint64_t r8 = state->regs()->read<uint64_t>(CPU_OFFSET(regs[8]));
    uint64_t r9 = state->regs()->read<uint64_t>(CPU_OFFSET(regs[9]));

    g_s2e->getInfoStream(state)
        << "syscall: " << klee::hexval(rax) << " ("
        << klee::hexval(rdi) << ", " << klee::hexval(rsi) << ", "
        << klee::hexval(rdx) << ", " << klee::hexval(r10) << ", "
        << klee::hexval(r8) << ", " << klee::hexval(r9) << ")\n";
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
