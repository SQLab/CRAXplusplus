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

#ifndef S2E_PLUGINS_REQUIEM_ROP_CHAIN_BUILDER_H
#define S2E_PLUGINS_REQUIEM_ROP_CHAIN_BUILDER_H

#include <vector>

namespace s2e::plugins::requiem {

// Requiem supports two modes of ROP chain generation:
// 1. Symbolic mode (usually used before stack pivoting)
// 2. Direct mode (usually used after stack pivoting)

// Forward declaration
class Requiem;
class Exploit;
class Technique;

class RopChainBuilder {
public:
    explicit RopChainBuilder(Requiem &ctx)
        : m_ctx(ctx),
          m_symbolicMode(true),
          m_symbolicModeRspOffset() {}


    [[nodiscard]]
    bool build(Exploit &exploit,
               const std::vector<Technique *> &techniques);

private:
    [[nodiscard]]
    bool shouldSwitchToDirectMode(const Technique *t) const;

    // When building ROP chain using symbolic mode,
    // exploit constraints are added to the input constraints
    // in order to generate ROP payload.
    [[nodiscard]]
    bool addRegisterConstraint(Register reg, uint64_t value);

    [[nodiscard]]
    bool addMemoryConstraint(uint64_t virtAddr, uint64_t value);
    

    Requiem &m_ctx;
    bool m_symbolicMode;  // true: symbolic, false: direct
    uint32_t m_symbolicModeRspOffset;
};

}  // namespace s2e::plugins::requiem

#endif  // S2E_PLUGINS_REQUIEM_ROP_CHAIN_BUILDER_H
