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
#include <s2e/Plugins/Requiem/Pwnlib/ELF.h>

#include <string>
#include <fstream>
#include <sstream>

#include "Requiem.h"

using namespace klee;
namespace py = pybind11;

typedef std::pair<std::string, std::vector<unsigned char>> VarValuePair;
typedef std::vector<VarValuePair> ConcreteInputs;

namespace s2e::plugins::requiem {

S2E_DEFINE_PLUGIN(Requiem, "Automatic Exploit Generation Engine", "", );


Requiem::Requiem(S2E *s2e)
    : Plugin(s2e),
      m_state(),
      m_linuxMonitor(),
      m_pybind11(),
      m_pwnlib(py::module::import("pwnlib.elf")),
      m_registerManager(*this),
      m_memoryManager(*this),
      m_disassembler(*this),
      m_exploit(*this,
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
            sigc::mem_fun(*this, &Requiem::onSymbolicRip));
}


void Requiem::onSymbolicRip(S2EExecutionState *state,
                            klee::ref<klee::Expr> symbolicRip,
                            uint64_t concreteRip,
                            bool &concretize,
                            CorePlugin::symbolicAddressReason reason) {
    if (reason != CorePlugin::symbolicAddressReason::PC) {
        return;
    }

    m_state = state;

    log<WARN>()
        << "Detected symbolic RIP: " << hexval(concreteRip)
        << ", original value is: " << hexval(state->regs()->getPc())
        << "\n";

    reg().setRipSymbolic(symbolicRip);

    // Dump CPU registers.
    reg().showRegInfo();

    // Dump virtual memory mappings.
    mem().showMapInfo(m_target_process_pid);

    // Disassembler test.
    /*
    os << "__libc_csu_init = " << hexval(m_exploit.getElf().symbols()["__libc_csu_init"]) << "\n";

    for (auto insn : m_disassembler.disasm(state, "__libc_csu_init")) {
        os << hexval(insn.address) << ": " << insn.mnemonic << " " << insn.op_str << "\n";
    }
    */

    // Constraints test
    /*
    os << "dumping input constraints...\n";
    for (auto expr : state->constraints().getConstraintSet()) {
        os << expr << "\n";
    }
    */

    // RBP constraint
    klee::ref<klee::Expr> rbpConstraint
        = klee::EqExpr::create(
                reg().readSymbolic(Register::RBP),
                klee::ConstantExpr::create(0xaabbccdd, klee::Expr::Int64));

    // Adding RIP constraint to the current execution state.
    klee::ref<klee::Expr> ripConstraint
        = klee::EqExpr::create(
                symbolicRip,
                klee::ConstantExpr::create(0xdeadbeef, klee::Expr::Int64));

    klee::ref<klee::Expr> rspConstraint
        = klee::EqExpr::create(
                mem().readSymbolic(reg().readConcrete(Register::RSP), klee::Expr::Int64),
                klee::ConstantExpr::create(0xcafebabe, klee::Expr::Int64));

    klee::ref<klee::Expr> rsp8Constraint
        = klee::EqExpr::create(
                mem().readSymbolic(reg().readConcrete(Register::RSP) + 8, klee::Expr::Int64),
                klee::ConstantExpr::create(0x77885566, klee::Expr::Int64));

    /*
    bool isSym = state->mem()->symbolic(rspConcrete, 8);
    os << "RSP = " << hexval(rspConcrete) << "\n";
    os << "is *RSP symbolic ? " << isSym << "\n";
    */

    (void) m_state->addConstraint(rbpConstraint, /*recomputeConcolics=*/true);
    (void) m_state->addConstraint(ripConstraint, /*recomputeConcolics=*/true);
    //(void) state->addConstraint(rspConstraint, /*recomputeConcolics=*/true);
    //(void) state->addConstraint(rsp8Constraint, /*recomputeConcolics=*/true);

    ConcreteInputs newInput;

    if (m_state->getSymbolicSolution(newInput)) {
        static int counter = 0;
        std::string filename = "exploit" + std::to_string(counter++) + ".bin";

        log<WARN>() << "Generated exploit: " << filename << "\n";
        std::stringstream ss;

        const VarValuePair &vp = newInput.front();
        for (const auto _byte : vp.second) {
            ss << _byte;
        }

        std::ofstream ofs("exploit.bin", std::ios::binary);
        ofs << ss.rdbuf();
    } else {
        log<WARN>() << "Could not get symbolic solutions\n";
    }

    g_s2e->getExecutor()->terminateState(*state, "End of exploit generation");
}

void Requiem::onProcessLoad(S2EExecutionState *state,
                            uint64_t cr3,
                            uint64_t pid,
                            const std::string &imageFileName) {
    m_state = state;

    log<WARN>() << "onProcessLoad: " << imageFileName << "\n";

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
    m_state = state;

    if (pc == m_exploit.getElf().symbols()["main"]) {
        log<WARN>() << "reached main()\n";
    }

    if (m_linuxMonitor->isKernelAddress(pc)) {
        return;
    }

    onInstructionExecute->connect(
            sigc::mem_fun(*this, & Requiem::instructionHook));
}

void Requiem::instructionHook(S2EExecutionState *state, uint64_t pc) {
    m_state = state;

    Instruction i = m_disassembler.disasm(pc);

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
    m_state = state;

    log<INFO>()
        << "syscall: " << hexval(reg().readConcrete(Register::RAX)) << " ("
        << hexval(reg().readConcrete(Register::RDI)) << ", "
        << hexval(reg().readConcrete(Register::RSI)) << ", "
        << hexval(reg().readConcrete(Register::RDX)) << ", "
        << hexval(reg().readConcrete(Register::R10)) << ", "
        << hexval(reg().readConcrete(Register::R8)) << ", "
        << hexval(reg().readConcrete(Register::R9)) << ")\n";
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
