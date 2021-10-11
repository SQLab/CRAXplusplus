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

#ifndef S2E_PLUGINS_REQUIEM_DISASSEMBLER_H
#define S2E_PLUGINS_REQUIEM_DISASSEMBLER_H

#include <string>
#include <vector>

#include <s2e/S2E.h>
#include <s2e/S2EExecutionState.h>

namespace s2e::plugins::requiem {

struct Instruction {
    uint64_t address;
    std::string mnemonic;
    std::string op_str;
};


// Forward declaration
class Requiem;

class Disassembler {
public:
    explicit Disassembler(Requiem &ctx) : m_ctx(ctx) {}

    // Disassemble one instruction at the specificed address.
    Instruction disasm(const uint64_t pc);

    // Disassemble all instructions in the given `code` vector,
    // where the `code` is assumed to be loaded at `virtAddr`.
    std::vector<Instruction> disasm(const std::vector<uint8_t> &code,
                                    const uint64_t virtAddr);

    // Disassemble a function by its symbol.
    std::vector<Instruction> disasm(const std::string &symbol);

private:
    Requiem &m_ctx;
};

}  // namespace s2e::plugins::requiem

#endif  // S2E_PLUGINS_REQUIEM_DISASSEMBLER_H
