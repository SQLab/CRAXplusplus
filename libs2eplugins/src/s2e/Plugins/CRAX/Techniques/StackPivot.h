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

// Forward declaration
class CRAX;

class StackPivot : public Technique {
public:
    explicit StackPivot(CRAX &ctx) : Technique(ctx) {}
    virtual ~StackPivot() = default;
};

class BasicStackPivot : public StackPivot {
public:
    explicit BasicStackPivot(CRAX &ctx);
    virtual ~BasicStackPivot() = default;

    virtual void initialize() override;
    virtual bool checkRequirements() const override;
    virtual void resolveRequiredGadgets() override;
    virtual std::string getAuxiliaryFunctions() const override;

    virtual std::vector<SymbolicRopPayload> getSymbolicRopPayloadList() const override;
    virtual ConcreteRopPayload getExtraPayload() const override;

    virtual std::string toString() const override;
};

class AdvancedStackPivot : public StackPivot {
public:
    explicit AdvancedStackPivot(CRAX &ctx);
    virtual ~AdvancedStackPivot() = default;

    virtual void initialize() override;
    virtual bool checkRequirements() const override;
    virtual void resolveRequiredGadgets() override;
    virtual std::string getAuxiliaryFunctions() const override;

    virtual std::vector<SymbolicRopPayload> getSymbolicRopPayloadList() const override;
    virtual ConcreteRopPayload getExtraPayload() const override;

    virtual std::string toString() const override;

private:
    // XXX: This is temporary
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

    void beforeExploitGeneration();

    uint64_t determineRetAddr(uint64_t readCallSiteAddr) const;


    uint32_t m_offsetToRetAddr;

    // 40121a:   e8 51 fe ff ff    call 401070 <read@plt>
    // 0x40121a is a call site of read@libc.
    std::set<ReadCallSiteInfo, ReadCallSiteInfoCmp> m_readCallSites;
};

}  // namespace s2e::plugins::crax

#endif  // S2E_PLUGINS_CRAX_STACK_PIVOT_H
