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
#include <s2e/Plugins/CRAX/Pwnlib/Function.h>

#include <capstone/capstone.h>

#include <cassert>

#include "Disassembler.h"

#define X86_64_INSN_MAX_NR_BYTES 15

namespace s2e::plugins::crax {

std::optional<Instruction> Disassembler::disasm(uint64_t pc) const {
    std::vector<uint8_t> code = mem().readConcrete(pc, X86_64_INSN_MAX_NR_BYTES);
    std::vector<Instruction> insns = disasm(code, pc);

    if (insns.empty()) {
        return std::nullopt;
    } else {
        return insns.front();
    }
}

std::vector<Instruction> Disassembler::disasm(const std::string &symbol) const {
    // The object `f` holds the information about the function `symbol`,
    // e.g., offset within ELF, size, etc.
    const auto &elf = g_crax->getExploit().getElf();
    Function f = elf.functions().at(symbol);
    std::vector<uint8_t> code = mem().readConcrete(elf.getBase() + f.address, f.size);
    std::vector<Instruction> insns = disasm(code, elf.getBase() + f.address);

    assert(insns.size());
    return insns;
}

std::vector<Instruction> Disassembler::disasm(const std::vector<uint8_t> &code,
                                              uint64_t virtAddr,
                                              bool warnOnError) const {
    csh handle;
    cs_insn *insn;
    size_t count;
    std::vector<Instruction> ret;

    if (code.empty()) {
        return ret;
    }

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        return ret;
    }

    count = cs_disasm(handle, code.data(), code.size(), virtAddr, 0, &insn);

    if (count) {
        ret.resize(count);
        for (size_t i = 0; i < count; i++) {
            ret[i] = {
                insn[i].address,
                insn[i].size,
                insn[i].mnemonic,
                insn[i].op_str
            };
        }
        cs_free(insn, count);
    } else if (warnOnError) {
        auto &os = log<WARN>();
        os << "disassemble failed at " << klee::hexval(virtAddr) << ": ";

        for (size_t i = 0; i < code.size(); i++) {
            os << hexval(code[i]);
            if (i != code.size() - 1) {
                os << " ";
            }
        }
        os << "\n";
    }

    cs_close(&handle);
    return ret;
}


Disassembler &disas(S2EExecutionState *state) {
    return g_crax->disas(state);
}

}  // namespace s2e::plugins::crax
