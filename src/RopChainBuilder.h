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

#ifndef S2E_PLUGINS_CRAX_ROP_CHAIN_BUILDER_H
#define S2E_PLUGINS_CRAX_ROP_CHAIN_BUILDER_H

#include <klee/Expr.h>
#include <s2e/Plugins/CRAX/API/Register.h>
#include <s2e/Plugins/CRAX/API/Memory.h>

#include <vector>

namespace s2e::plugins::crax {

// To begin with, each exploitation technique can contain N * ROP subchains.
// The task of RopChainBuilder is to concatenate the subchains of each
// technique into a single complete ROP chain.
//
// CRAX supports two modes of ROP chain generation:
// 1. Symbolic mode (usually used before stack pivoting)
// 2. Direct mode (usually used after stack pivoting)

// Forward declaration
class CRAX;
class Exploit;
class Technique;

class RopChainBuilder {
    using ConcreteInput = std::vector<uint8_t>;
    using VarValuePair = std::pair<std::string, ConcreteInput>;
    using ConcreteInputs = std::vector<VarValuePair>;

public:
    RopChainBuilder();
    ~RopChainBuilder() = default;

    void reset();

    [[nodiscard]]
    bool addRegisterConstraint(Register::X64 r,
                               const klee::ref<klee::Expr> &e) const;

    [[nodiscard]]
    bool addMemoryConstraint(uint64_t addr,
                             const klee::ref<klee::Expr> &e) const;

    [[nodiscard]]
    bool chain(const Technique &technique);

    [[nodiscard]]
    const std::vector<RopSubchain> &build();

private:
    [[nodiscard]]
    bool doChainSymbolic(const Technique &technique);

    [[nodiscard]]
    bool doChainDirect(const Technique &technique);

    [[nodiscard]]
    bool shouldSwitchToDirectMode(const Technique *t) const;

    bool buildStage1Payload();

    [[nodiscard]]
    ConcreteInputs getConcreteInputs() const;

    [[nodiscard]]
    ConcreteInput getFirstConcreteInput() const;


    bool m_isSymbolicMode;  // true: symbolic, false: direct
    bool m_shouldSkipSavedRbp;
    uint32_t m_rspOffset;
    std::vector<RopSubchain> m_ropChain;
};

}  // namespace s2e::plugins::crax

#endif  // S2E_PLUGINS_CRAX_ROP_CHAIN_BUILDER_H
