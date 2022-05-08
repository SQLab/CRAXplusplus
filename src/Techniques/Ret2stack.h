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

#ifndef S2E_PLUGINS_CRAX_RET2STACK_H
#define S2E_PLUGINS_CRAX_RET2STACK_H

#include <s2e/Plugins/CRAX/Techniques/Technique.h>

#include <cstdlib>

namespace s2e::plugins::crax {

class Ret2stack : public Technique {
public:
    Ret2stack();
    virtual ~Ret2stack() override = default;

    virtual void initialize() override;
    virtual std::string toString() const override { return "Ret2stack"; }

    virtual std::vector<RopPayload> getRopPayloadList() const override;
    virtual RopPayload getExtraRopPayload() const override { return {}; }

private:
    std::vector<uint8_t> initShellcode();

    // Attempts to inject shellcode into the specified symbolic memory block
    // with the longest NOP sled possible. Returns the exploit constraint
    // on success, otherwise a false klee::Expr.
    klee::ref<klee::Expr> analyzeSymbolicBlock(S2EExecutionState &state,
                                               uint64_t symBlockBase,
                                               uint64_t symBlockSize) const;

    inline bool isOverlapped(uint64_t x, uint64_t y) const {
        return ((x == y) || (std::abs((int64_t) (x - y)) == 1));
    }


    klee::ref<klee::Expr> injectShellcodeAt(uint64_t addr) const;

    klee::ref<klee::Expr> injectNopSledBetween(uint64_t lowerbound,
                                               uint64_t upperbound) const;

    klee::ref<klee::Expr> setRipBetween(uint64_t lowerbound,
                                        uint64_t upperbound) const;

    void generateExploit(S2EExecutionState &state,
                         const klee::ref<klee::Expr> &constraints,
                         std::string filename) const;


    static const std::string s_defaultShellcode;

    std::vector<uint8_t> m_shellcode;
    klee::ref<klee::Expr> m_exploitConstraint;
};

}  // namespace s2e::plugins::crax

#endif  // S2E_PLUGINS_CRAX_RET2STACK_H
