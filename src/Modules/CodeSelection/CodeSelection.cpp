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

#include <algorithm>

#include "CodeSelection.h"

using namespace klee;

namespace s2e::plugins::crax {

CodeSelection::CodeSelection()
    : Module(),
      m_functions(g_s2e->getConfig()->getStringList(getConfigKey())),
      m_autoMode(m_functions.empty()),
      m_symMemRegMap(initSymMemRegMap()) {
    auto functionMonitor = g_s2e->getPlugin<FunctionMonitor>();

    if (!functionMonitor) {
        log<WARN>() << "CodeSelection requires S2E's FunctionMonitor plugin.\n";
        exit(1);
    }

    functionMonitor->onCall.connect(
            sigc::mem_fun(*this, &CodeSelection::onFunctionCall));
}


CodeSelection::SymMemRegMap CodeSelection::initSymMemRegMap() {
    return {
        { "lstat",  { Register::X64::RDI } },
        { "perror", { Register::X64::RDI } },
    };
}

bool CodeSelection::checkRequirements() const {
    Exploit &exploit = g_crax->getExploit();
    return exploit.getElf().plt().size();
}

void CodeSelection::onFunctionCall(S2EExecutionState *state,
                                   const ModuleDescriptorConstPtr &callerModule,
                                   const ModuleDescriptorConstPtr &calleeModule,
                                   uint64_t callerPc,
                                   uint64_t calleePc,
                                   const FunctionMonitor::ReturnSignalPtr &onRet) {
    assert(onRet);

    if (!callerModule || callerModule->Name != VirtualMemoryMap::s_elfLabel) {
        return;
    }

    g_crax->setCurrentState(state);

    Exploit &exploit = g_crax->getExploit();
    const ELF &elf = exploit.getElf();

    llvm::SmallVector<Register::X64, 1> args = {
        Register::X64::RDI,
        Register::X64::RSI,
        Register::X64::RDX,
        Register::X64::RCX,
        Register::X64::R8,
        Register::X64::R9,
    };

    bool shouldProceed = false;
    std::string symbol;

    if (m_autoMode) {
        auto it = elf.inversePlt().find(calleePc);
        shouldProceed = it != elf.inversePlt().end();
        if (shouldProceed) {
            symbol = it->second;
        }

    } else {
        for (const auto &funcSym : m_functions) {
            auto it = elf.symbols().find(funcSym);
            if (it != elf.symbols().end() && it->second == calleePc) {
                shouldProceed = true;
                symbol = it->first;
                break;
            }
        }
    }

    if (!shouldProceed) {
        return;
    }

    log<WARN>() << "CodeSelection: " << symbol << '\n';

    ConcretizedRegionDescriptor crd;

    auto it = m_symMemRegMap.find(symbol);
    if (it != m_symMemRegMap.end()) {
        args = it->second;
    }

    for (auto arg : args) {
        uint64_t addr = reg().readConcrete(arg);
        uint64_t size = getSymBlockLen(state, addr);

        if (size) {
            log<WARN>()
                << "Temporarily concretizing the region pointed to by "
                << reg().getName(arg) << '\n';

            // Save the current path constraints.
            if (crd.exprs.empty()) {
                crd.constraints = state->constraints();
            }

            // Save the expression of this symbolic block.
            ref<Expr> e = mem().readSymbolic(addr, size * Expr::Int8);

            // Temporarily concretize this symbolic block.
            static_cast<void>(mem().readConcrete(addr, size, /*concretize=*/true));

            crd.exprs.push_back({ addr, e });
        }
    }

    // If any of the arguments points to a symbolic block, then we must
    // have concretized the block(s). As a result, we need to symbolize
    // them again later when the libc function is about to return.
    if (crd.exprs.size()) {
        auto modState = g_crax->getModuleState(state, this);
        modState->onFunctionCall(std::move(crd));
        onRet->connect(sigc::mem_fun(*this, &CodeSelection::onFunctionReturn));
    }
}

void CodeSelection::onFunctionReturn(S2EExecutionState *state,
                                     const ModuleDescriptorConstPtr &retSiteModule,
                                     const ModuleDescriptorConstPtr &retTargetModule,
                                     uint64_t retSite) {
    if (!retTargetModule || retTargetModule->Name != VirtualMemoryMap::s_elfLabel) {
        return;
    }

    g_crax->setCurrentState(state);

    auto modState = g_crax->getModuleState(state, this);
    auto crd = modState->onFunctionRet();

    for (const auto &entry : crd.exprs) {
        uint64_t addr = entry.first;
        ref<Expr> expr = entry.second;

        // Restore symbolic expressions.
        log<WARN>() << "Restoring symbolic expressions to: " << hexval(addr) << '\n';
        static_cast<void>(mem().writeSymbolic(addr, expr));
    }

    // Forcibly restore path constraints to `state` (deep copy).
    ConstraintManager &constraints = const_cast<ConstraintManager &>(state->constraints());
    constraints = crd.constraints;
}


uint64_t CodeSelection::getSymBlockLen(S2EExecutionState *state, uint64_t ptr) {
    g_crax->setCurrentState(state);

    uint64_t len = 0;
    for (; mem().isMapped(ptr) && mem().isSymbolic(ptr, 1); ptr++, len++) {}

    return len;
}

}  // namespace s2e::plugins::crax
