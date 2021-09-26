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

#include "Disassembler.h"

#include <capstone/capstone.h>

#define X86_64_INSN_MAX_NR_BYTES 15

namespace s2e::plugins::requiem {

Instruction Disassembler::disasm(S2EExecutionState *state,
                                 uint64_t pc) {
    uint8_t code[X86_64_INSN_MAX_NR_BYTES] = {};
    csh handle;
    cs_insn *insn;
    size_t count;
    Instruction ret;

    if (!state->mem()->read(pc, code, sizeof(code) - 1)) {
        g_s2e->getWarningsStream() << "cannot read from memory at: " << klee::hexval(pc) << "\n";
        return ret;
    }

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        return ret;
    }

    count = cs_disasm(handle, code, sizeof(code) - 1, pc, 0, &insn);

    if (count) {
        ret.address = pc;
        ret.mnemonic = insn[0].mnemonic;
        ret.op_str = insn[0].op_str;
        cs_free(insn, count);
    }

    static_cast<void>(m_ctx);

    cs_close(&handle);
    return ret;
}

std::vector<Instruction> Disassembler::disasm(S2EExecutionState *state,
                                              const std::string &symbol) {
    return {};
}

}  // namespace s2e::plugins::requiem
