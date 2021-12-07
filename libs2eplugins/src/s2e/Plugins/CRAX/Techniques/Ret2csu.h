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

#ifndef S2E_PLUGINS_CRAX_RET2CSU_H
#define S2E_PLUGINS_CRAX_RET2CSU_H

#include <s2e/Plugins/CRAX/Techniques/Technique.h>

#include <exception>
#include <map>
#include <string>
#include <vector>

namespace s2e::plugins::crax {

// Forward declaration
class CRAX;

class Ret2csu : public Technique {
public:
    class UnhandledPlaceholderException : public std::exception {
    public:
        UnhandledPlaceholderException() = default;
        virtual ~UnhandledPlaceholderException() = default;

        virtual const char *what() const throw() {
            return "Unhandled placeholder expr found";
        }
    };


    Ret2csu(CRAX &ctx);
    virtual ~Ret2csu() = default;

    virtual bool checkRequirements() const override;
    virtual void resolveRequiredGadgets() override;
    virtual std::string getAuxiliaryFunctions() const override;

    virtual std::vector<SymbolicRopPayload> getSymbolicRopPayloadList() const override;
    virtual ConcreteRopPayload getExtraPayload() const override;

    virtual std::string toString() const override;

    std::vector<SymbolicRopPayload> getSymbolicRopPayloadList(uint64_t addr,
                                                              uint64_t arg1,
                                                              uint64_t arg2,
                                                              uint64_t arg3) const;

    static const std::string s_libcCsuInit;
    static const std::string s_libcCsuInitGadget1;
    static const std::string s_libcCsuInitGadget2;
    static const std::string s_libcCsuInitCallTarget;

private:
    void parseLibcCsuInit();
    void searchGadget2CallTarget(std::string funcName = "_fini");
    void buildSymbolicRopPayloadList();
    void buildAuxiliaryFunction();

    uint64_t m_addr;
    uint64_t m_arg1;
    uint64_t m_arg2;
    uint64_t m_arg3;

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

    std::vector<SymbolicRopPayload> m_symbolicRopPayloadList;
    std::string m_auxiliaryFunction;
};

}  // namespace s2e::plugins::crax

#endif  // S2E_PLUGINS_CRAX_RET2CSU_H
