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
#include <s2e/Plugins/CRAX/API/VirtualMemoryMap.h>

#include "CodeSelection.h"

using namespace klee;

namespace s2e::plugins::crax {

CodeSelection::CodeSelection()
    : Module(),
      m_functions() {
    auto functionMonitor = g_s2e->getPlugin<FunctionMonitor>();

    functionMonitor->onCall.connect(
            sigc::mem_fun(*this, &CodeSelection::onFunctionCall));

    std::vector<std::string> funcs
        = g_s2e->getConfig()->getStringList(getConfigKey());

    for (const auto &f : funcs) {
        m_functions.push_back(f);
    }
}


void CodeSelection::onFunctionCall(S2EExecutionState *state,
                                   const ModuleDescriptorConstPtr &callerModule,
                                   const ModuleDescriptorConstPtr &calleeModule,
                                   uint64_t callerPc,
                                   uint64_t calleePc,
                                   const FunctionMonitor::ReturnSignalPtr &onRet) {
    if (!callerModule || callerModule->Name != VirtualMemoryMap::s_elfLabel) {
        return;
    }

    Exploit &exploit = g_crax->getExploit();
    ELF &elf = exploit.getElf();

    for (const auto &funcSym : m_functions) {
        auto it = elf.symbols().find(funcSym);

        if (it != elf.symbols().end() && it->second == calleePc) {
            log<INFO>() << "Temporarily concretizing the region pointed to by RDI\n";

            klee::ConstraintManager constraints = state->constraints();

            // Get the length of symbolic C-string pointed to by RDI.
            uint64_t rdi = reg(state).readConcrete(Register::X64::RDI);
            uint64_t len = guestStrlen(state, rdi);

            // Save symbolic expression.
            ref<Expr> expr = mem(state).readSymbolic(rdi, len * Expr::Int8);

            // Temporarily concretize the string.
            (void) mem(state).readConcrete(rdi, len, /*concretize=*/true);

            auto modState = g_crax->getModuleState(state, this);
            modState->onFunctionCall({ funcSym, rdi, constraints, expr });

            if (onRet) {
                onRet->connect(
                        sigc::mem_fun(*this, &CodeSelection::onFunctionReturn));
            }
            break;
        }
    }
}

void CodeSelection::onFunctionReturn(S2EExecutionState *state,
                                     const ModuleDescriptorConstPtr &retSiteModule,
                                     const ModuleDescriptorConstPtr &retTargetModule,
                                     uint64_t retSite) {
    if (!retTargetModule || retTargetModule->Name != VirtualMemoryMap::s_elfLabel) {
        return;
    }

    auto modState = g_crax->getModuleState(state, this);
    FuncCtx funcCtx = modState->onFunctionRet();

    // Restore symbolic expressions.
    log<INFO>() << "Restoring symbolic expressions to: " << hexval(funcCtx.rdi) << '\n';
    (void) mem(state).writeSymbolic(funcCtx.rdi, funcCtx.expr);

    // Forcibly restore path constraints.
    ConstraintManager &constraints = const_cast<ConstraintManager &>(state->constraints());
    constraints = funcCtx.constraints;
}


uint64_t CodeSelection::guestStrlen(S2EExecutionState *state, uint64_t ptr) {
    uint64_t len = 0;
    bool ok = false;
    uint8_t c;

    do {
        c = 0;
        ok = state->mem()->read(ptr++, &c, VirtualAddress, /*addConstraint=*/false);
        // mem(state).readConcrete(ptr, sizeof(uint8_t), /*concretize=*/false);
        if (!ok) {
            break;
        }
        if (c) {
            len++;
        }
    } while (c);

    return len;
}

}  // namespace s2e::plugins::crax
