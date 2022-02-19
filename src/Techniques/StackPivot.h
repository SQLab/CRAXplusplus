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

#ifndef S2E_PLUGINS_CRAX_STACK_PIVOT_H
#define S2E_PLUGINS_CRAX_STACK_PIVOT_H

#include <s2e/Plugins/CRAX/API/Disassembler.h>
#include <s2e/Plugins/CRAX/Techniques/Technique.h>

#include <map>
#include <set>
#include <string>
#include <vector>

namespace s2e::plugins::crax {

class StackPivot : public Technique {
public:
    StackPivot() : Technique() {}
    virtual ~StackPivot() override = default;

    virtual void resolveRequiredGadgets() override;
};

class BasicStackPivot : public StackPivot {
public:
    BasicStackPivot();
    virtual ~BasicStackPivot() override = default;

    virtual std::string toString() const override { return "BasicStackPivot"; }

    virtual std::vector<RopSubchain> getRopSubchains() const override;
    virtual RopSubchain getExtraRopSubchain() const override;
};

class AdvancedStackPivot : public StackPivot {
public:
    AdvancedStackPivot();
    virtual ~AdvancedStackPivot() override = default;

    virtual void initialize() override;
    virtual bool checkRequirements() const override;
    virtual std::string toString() const override { return "AdvancedStackPivot"; }

    virtual std::vector<RopSubchain> getRopSubchains() const override;
    virtual RopSubchain getExtraRopSubchain() const override { return {}; }

private:
    struct ReadCallSiteInfo {
        uint64_t address;
        uint64_t buf;
        uint64_t len;
    };

    struct ReadCallSiteInfoCmp {
        bool operator ()(const ReadCallSiteInfo &i1,
                         const ReadCallSiteInfo &i2) const {
            return i1.address < i2.address;
        }
    };


    void maybeInterceptReadCallSites(S2EExecutionState *state,
                                     const Instruction &i);

    void beforeExploitGeneration(S2EExecutionState *state);

    void initDynamicRopConstraintsOnce() const;

    uint64_t determineRetAddr(uint64_t readCallSiteAddr,
                              int &rbpOffset) const;


    uint32_t m_offsetToRetAddr;

    // 40121a:   e8 51 fe ff ff    call 401070 <read@plt>
    // 0x40121a is a call site of read@libc.
    std::set<ReadCallSiteInfo, ReadCallSiteInfoCmp> m_readCallSites;
};

}  // namespace s2e::plugins::crax

#endif  // S2E_PLUGINS_CRAX_STACK_PIVOT_H
