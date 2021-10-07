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

#ifndef S2E_PLUGINS_REQUIEM_REGISTER_MANAGER_H
#define S2E_PLUGINS_REQUIEM_REGISTER_MANAGER_H

#include <s2e/S2EExecutionState.h>

#include <array>
#include <vector>

namespace s2e::plugins::requiem {

// Forward declaration.
class Requiem;

// libcpu/include/cpu/i386/defs.h
enum Register {
    RAX,  // 0
    RCX,  // 1
    RDX,  // 2
    RBX,  // 3
    RSP,  // 4
    RBP,  // 5
    RSI,  // 6
    RDI,  // 7
    R8,   // 8
    R9,   // 9
    R10,  // 10
    R11,  // 11
    R12,  // 12
    R13,  // 13
    R14,  // 14
    R15,  // 15
    LAST,
    RIP
};


// x86_64 Register Manager.
class RegisterManager {
public:
    explicit RegisterManager(Requiem &ctx);
    void initialize();


    // Determine if the given register contains symbolic data.
    [[nodiscard]]
    bool isSymbolic(Register reg);

    // Read symbolic data from the register file.
    [[nodiscard]]
    klee::ref<klee::Expr> readSymbolic(Register reg);

    // Read concrete data from the register file.
    [[nodiscard]]
    uint64_t readConcrete(Register reg);

    // Dump all register values.
    void showRegInfo();

    void setRipSymbolic(klee::ref<klee::Expr> ripExpr);

private:
    static const std::array<std::string, 10> s_regs32;
    static const std::array<std::string, 18> s_regs64;

    // Requiem's attributes.
    Requiem &m_ctx;

    // libcpu mandates that RIP should never become symbolic,
    // hence we'll maintain an extra flag.
    bool m_isRipSymbolic;
    klee::ref<klee::Expr> m_ripExpr;
};

}  // namespace s2e::plugins::requiem

#endif  // S2E_PLUGINS_REQUIEM_REGISTER_MANAGER_H
