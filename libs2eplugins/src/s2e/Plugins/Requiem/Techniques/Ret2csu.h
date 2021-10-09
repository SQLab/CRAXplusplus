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

#ifndef S2E_PLUGINS_REQUIEM_RET2CSU_H
#define S2E_PLUGINS_REQUIEM_RET2CSU_H

#include <s2e/Plugins/Requiem/Techniques/Technique.h>

#include <map>
#include <string>
#include <vector>

namespace s2e::plugins::requiem {

// Forward declaration
class Requiem;

class Ret2csu : public Technique {
public:
    Ret2csu(Requiem &ctx,
            std::string arg1 = "",
            std::string arg2 = "",
            std::string arg3 = "",
            std::string addr = "");
    virtual ~Ret2csu() = default;

    virtual bool checkRequirements() const override;
    virtual void resolveRequiredGadgets() override;
    virtual std::string getAuxiliaryFunctions() const override;
    virtual std::vector<std::vector<std::string>> getRopChainsList() const override;
    virtual std::vector<std::string> getExtraPayload() const override;

    std::vector<std::vector<std::string>>
    getRopChainsListWithArgs(const std::string &arg1,
                             const std::string &arg2,
                             const std::string &arg3,
                             const std::string &addr,
                             bool arg1IsRdi = false) const;
protected:
    void parseLibcCsuInit();
    void searchGadget2CallTarget(std::string funcName = "_fini");
    void buildRopChainsList();
    void buildAuxiliaryFunction();

    std::string m_arg1;
    std::string m_arg2;
    std::string m_arg3;
    std::string m_addr;

    // The following attributes will be initialized in
    // `Ret2csu::parseLibcCsuInit()` and `Ret2csu::buildAuxiliaryFunction()`.
    uint64_t m_libcCsuInit;
    uint64_t m_libcCsuInitGadget1;
    uint64_t m_libcCsuInitGadget2;
    uint64_t m_libcCsuInitCallTarget;

    std::vector<std::string> m_gadget1Regs;
    std::map<std::string, std::string> m_gadget2Regs;
    std::string m_gadget2CallReg1;
    std::string m_gadget2CallReg2;

    std::vector<std::vector<std::string>> m_ropChainsList;
    std::string m_auxiliaryFunction;
};

}  // namespace s2e::plugins::requiem

#endif  // S2E_PLUGINS_REQUIEM_RET2CSU_H
