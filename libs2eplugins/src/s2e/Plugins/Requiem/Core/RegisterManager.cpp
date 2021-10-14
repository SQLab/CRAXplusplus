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

#include <s2e/S2E.h>
#include <s2e/S2EExecutionStateRegisters.h>
#include <s2e/Plugins/Requiem/Requiem.h>

#include "RegisterManager.h"

using namespace klee;

namespace s2e::plugins::requiem {

const std::array<std::string, 10> RegisterManager::s_regs32 = {
    "EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI"
};

const std::array<std::string, 18> RegisterManager::s_regs64 = {
    "RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI",
    "R8", "R9",  "R10", "R11", "R12", "R13", "R14", "R15"
};


RegisterManager::RegisterManager(Requiem &ctx)
    : m_ctx(ctx),
      m_isRipSymbolic(),
      m_ripExpr() {}

void RegisterManager::initialize() {}


bool RegisterManager::isSymbolic(Register reg) {
    return !isa<klee::ConstantExpr>(readSymbolic(reg));
}

ref<Expr> RegisterManager::readSymbolic(Register reg) {
    // XXX: check result
    return m_ctx.state()->regs()->read(getOffset(reg), klee::Expr::Int64);
}

uint64_t RegisterManager::readConcrete(Register reg) {
    uint64_t ret;
    if (!m_ctx.state()->regs()->read(getOffset(reg), &ret, sizeof(ret), /*concretize=*/false)) {
        m_ctx.log<WARN>()
            << "Cannot read concrete data from register: " << getName(reg) << "\n";
    }
    return ret;
}

bool RegisterManager::writeSymbolic(Register reg, const klee::ref<klee::Expr> &value) {
    bool success = m_ctx.state()->regs()->write(getOffset(reg), value);
    if (!success) {
        m_ctx.log<WARN>()
            << "Cannot write symbolic data to register: " << getName(reg) << "\n";
    }
    return success;
}

bool RegisterManager::writeConcrete(Register reg, uint64_t value) {
    bool success = m_ctx.state()->regs()->write(getOffset(reg), &value, sizeof(value));
    if (!success) {
        m_ctx.log<WARN>()
            << "Cannot write concrete data to register: " << getName(reg) << "\n";
    }
    return success;
}

void RegisterManager::showRegInfo() {
    auto &os = m_ctx.log<WARN>();
    os << "---------- [REGISTERS] ----------\n";

    for (int i = 0; i < Register::LAST; i++) {
        auto reg = static_cast<Register>(i);
        os << getName(reg) << "\t";

        if (isSymbolic(reg)) {
            os << "(symbolic)";
        } else {
            os << hexval(readConcrete(reg));
        }
        os << "\n";
    }

    os << "RIP\t";
    if (m_isRipSymbolic) {
        os << "(symbolic)";
    } else {
        os << hexval(m_ctx.state()->regs()->getPc());
    }
    os << "\n";
}

void RegisterManager::setRipSymbolic(klee::ref<klee::Expr> ripExpr) {
    m_isRipSymbolic = true;
    m_ripExpr = ripExpr;
}

}  // namespace s2e::plugins::requiem
