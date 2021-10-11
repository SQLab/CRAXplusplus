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

#ifndef S2E_PLUGINS_REQUIEM_STACK_PIVOT_H
#define S2E_PLUGINS_REQUIEM_STACK_PIVOT_H

#include <s2e/Plugins/Requiem/Techniques/Technique.h>

#include <map>
#include <string>
#include <vector>

namespace s2e::plugins::requiem {

// Forward declaration
class Requiem;

class BasicStackPivot : public Technique {
public:
    explicit BasicStackPivot(Requiem &ctx);
    virtual ~BasicStackPivot() = default;

    virtual bool checkRequirements() const override;
    virtual void resolveRequiredGadgets() override;
    virtual std::string getAuxiliaryFunctions() const override;
    virtual std::vector<std::vector<std::string>> getRopChainsList() const override;
    virtual std::vector<std::string> getExtraPayload() const override;
    virtual std::string toString() const override;
};

class AdvancedStackPivot : public Technique {
public:
    explicit AdvancedStackPivot(Requiem &ctx);
    virtual ~AdvancedStackPivot() = default;

    virtual bool checkRequirements() const override;
    virtual void resolveRequiredGadgets() override;
    virtual std::string getAuxiliaryFunctions() const override;
    virtual std::vector<std::vector<std::string>> getRopChainsList() const override;
    virtual std::vector<std::string> getExtraPayload() const override;
    virtual std::string toString() const override;

protected:
    uint64_t determineOffset() const;
};

}  // namespace s2e::plugins::requiem

#endif  // S2E_PLUGINS_REQUIEM_STACK_PIVOT_H
