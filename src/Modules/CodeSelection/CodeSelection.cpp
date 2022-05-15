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

#include "CodeSelection.h"

using namespace klee;

namespace s2e::plugins::crax {

CodeSelection::CodeSelection()
    : Module(),
      m_functions(g_s2e->getConfig()->getStringList(getConfigKey())),
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
        { "printf", { /* check the first six args */ } },
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

    std::string symbol;

    if (!isCallingRegisteredLibraryFunction(calleePc, symbol)) {
        return;
    }

    log<WARN>() << "CodeSelection: " << symbol << "(): temporarily concretizing arguments\n";
    ConcretizedRegionDescriptor crd;

    for (auto arg : decideArgv(symbol)) {
        uint64_t addr = reg().readConcrete(arg, /*verbose=*/false);
        uint64_t size = getSymBlockLen(state, addr);

        if (size) {
            log<DEBUG>()
                << "Temporarily concretizing the region pointed to by "
                << reg().getName(arg) << ", size = " << size << '\n';

            // Save the current path constraints.
            if (crd.exprs.empty()) {
                crd.constraints = state->constraints();
            }

            // Save the expression of this symbolic block.
            ref<Expr> e = mem().readSymbolic(addr, size * Expr::Int8);

            // Temporarily concretize this symbolic block.
            static_cast<void>(mem().readConcrete(addr, size, /*concretize=*/true));

            crd.exprs.push_back(std::make_pair(addr, e));
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

    for (const auto &[addr, expr] : crd.exprs) {
        // Restore symbolic expressions.
        log<DEBUG>() << "Restoring symbolic expressions to: " << hexval(addr) << '\n';
        static_cast<void>(mem().writeSymbolic(addr, expr));
    }

    // Forcibly restore path constraints to `state` (deep copy).
    const_cast<ConstraintManager &>(state->constraints()) = crd.constraints;
}


bool CodeSelection::isCallingRegisteredLibraryFunction(uint64_t calleePc,
                                                       std::string &symbolOut) const {
    // TODO:
    // 0000000000403dc0 <__lstat>:
    // 403dc0:       f3 0f 1e fa             endbr64
    // 403dc4:       48 89 f2                mov    rdx,rsi
    // 403dc7:       48 89 fe                mov    rsi,rdi
    // 403dca:       bf 01 00 00 00          mov    edi,0x1
    // 403dcf:       e9 ec d4 ff ff          jmp    4012c0 <__lxstat@plt>
    //
    // >>> hex(elf.sym['lstat'])
    // '0x403dc0'
    // >>> hex(elf.plt['lstat'])
    // Traceback (most recent call last):
    // File "<stdin>", line 1, in <module>
    // KeyError: 'lstat'
    // >>> hex(elf.sym['__lxstat'])
    // '0x4012c4'
    // >>> hex(elf.plt['__lxstat'])
    // '0x4012c4'

    Exploit &exploit = g_crax->getExploit();
    const ELF &elf = exploit.getElf();
    bool ret = false;

    if (m_functions.size()) {
        for (const auto &funcSym : m_functions) {
            auto it = elf.symbols().find(funcSym);
            if (it != elf.symbols().end() && it->second == calleePc) {
                ret = true;
                symbolOut = it->first;
                break;
            }
        }
    } else {
        auto it = elf.inversePlt().find(calleePc);
        if (it != elf.inversePlt().end()) {
            ret = true;
            symbolOut = it->second;
        }
    }

    return ret;
}

CodeSelection::Argv CodeSelection::decideArgv(const std::string &symbol) const {
    // By default, we check the first six function arguments.
    Argv ret = {
        Register::X64::RDI,
        Register::X64::RSI,
        Register::X64::RDX,
        Register::X64::RCX,
        Register::X64::R8,
        Register::X64::R9,
    };

    // However, if we already know which arguments are pointers,
    // then we only need to check those arguments.
    auto it = m_symMemRegMap.find(symbol);
    return (it != m_symMemRegMap.end() && it->second.size()) ? it->second : ret;
}

uint64_t CodeSelection::getSymBlockLen(S2EExecutionState *state, uint64_t ptr) const {
    g_crax->setCurrentState(state);

    uint64_t len = 0;
    for (; mem().isMapped(ptr) && mem().isSymbolic(ptr, 1); ptr++, len++) {}

    return len;
}

}  // namespace s2e::plugins::crax
