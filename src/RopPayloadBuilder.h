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

#ifndef S2E_PLUGINS_CRAX_ROP_PAYLOAD_BUILDER_H
#define S2E_PLUGINS_CRAX_ROP_PAYLOAD_BUILDER_H

#include <klee/Expr.h>
#include <s2e/Plugins/CRAX/API/Register.h>
#include <s2e/Plugins/CRAX/API/Memory.h>

#include <vector>

namespace s2e::plugins::crax {

// To begin with, each exploitation technique can contain N * ROP subchains.
// The task of RopPayloadBuilder is to concatenate the subchains of each
// technique into a single complete ROP chain.
//
// CRAX supports two modes of ROP chain generation:
// 1. Symbolic mode (usually used before stack pivoting)
// 2. Direct mode (usually used after stack pivoting)

// Forward declaration
class Technique;

class RopPayloadBuilder {
    using ConcreteInput = std::vector<uint8_t>;
    using VarValuePair = std::pair<std::string, ConcreteInput>;
    using ConcreteInputs = std::vector<VarValuePair>;

public:
    RopPayloadBuilder();
    ~RopPayloadBuilder() = default;

    void reset();

    // Chain the ROP subchain from the given technique
    // with `m_ropPayload`, the ROP chain we've built so far.
    [[nodiscard]]
    bool chain(const Technique &technique);

    // Finalizes and returns the full ROP chain.
    [[nodiscard]]
    const std::vector<RopPayload> &build();

    [[nodiscard]]
    uint32_t getRspOffset() const { return m_rspOffset; }


    [[nodiscard]]
    static bool addRegisterConstraint(S2EExecutionState &state,
                                      Register::X64 r,
                                      const klee::ref<klee::Expr> &e);

    [[nodiscard]]
    static bool addMemoryConstraint(S2EExecutionState &state,
                                    uint64_t addr,
                                    const klee::ref<klee::Expr> &e);

    [[nodiscard]]
    static ConcreteInputs getConcreteInputs(S2EExecutionState &state);

    [[nodiscard]]
    static ConcreteInput getOneConcreteInput(S2EExecutionState &state);

private:
    [[nodiscard]]
    bool chainSymbolic(const Technique &technique);

    [[nodiscard]]
    bool chainDirect(const Technique &technique);

    void doChainDirect(const std::vector<RopPayload> &ropSubchains,
                       const RopPayload &extraRopPayload,
                       size_t ropSubchainsBegin = 0);

    void maybeConcretizePlaceholderExpr(ref<Expr> &e) const;

    [[nodiscard]]
    bool shouldSwitchToDirectMode(const Technique *t) const;

    bool buildStage1Payload();


    bool m_isSymbolicMode;  // true: symbolic, false: direct
    bool m_shouldSkipSavedRbp;
    uint32_t m_rspOffset;
    std::vector<RopPayload> m_ropPayload;
};

}  // namespace s2e::plugins::crax

#endif  // S2E_PLUGINS_CRAX_ROP_PAYLOAD_BUILDER_H