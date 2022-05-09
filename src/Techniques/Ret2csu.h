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

#include <s2e/Plugins/CRAX/Expr/Expr.h>
#include <s2e/Plugins/CRAX/Techniques/Technique.h>

#include <exception>
#include <map>

namespace s2e::plugins::crax {

class Ret2csu : public Technique {
public:
    class UnhandledPlaceholderException : public std::exception {
    public:
        UnhandledPlaceholderException() = default;
        virtual ~UnhandledPlaceholderException() override = default;

        virtual const char *what() const throw() override {
            return "Unhandled placeholder expr found";
        }
    };


    Ret2csu();
    virtual ~Ret2csu() override = default;

    virtual void initialize() override;
    virtual bool checkRequirements() const override;
    virtual void resolveRequiredGadgets() override;
    virtual std::string toString() const override { return "Ret2csu"; }

    virtual std::vector<RopPayload> getRopPayloadList() const override;
    virtual RopPayload getExtraRopPayload() const override { return {}; }

    std::vector<RopPayload>
    getRopPayloadList(const klee::ref<klee::Expr> &retAddr,
                      const klee::ref<klee::Expr> &arg1,
                      const klee::ref<klee::Expr> &arg2,
                      const klee::ref<klee::Expr> &arg3) const;

    std::vector<RopPayload>
    getRopPayloadList(uint64_t retAddr,
                      uint64_t arg1,
                      uint64_t arg2,
                      uint64_t arg3) const;

    // User-provided call target.
    void setGadget2CallTarget(uint64_t libcCsuInitCallTarget) {
        m_libcCsuInitCallTarget = libcCsuInitCallTarget;
        invalidate();
    }

    size_t estimateRopPayloadSize(uint64_t arg1) {
        // XXX: Don't hardcode the integer literal...
        size_t ret = m_ropSubchainTemplate[0].size();
        return hasExceeded32Bits(arg1) ? ret + 2 : ret;
    }

    static const std::string s_libcCsuInit;
    static const std::string s_libcCsuInitGadget1;
    static const std::string s_libcCsuInitGadget2;
    static const std::string s_libcCsuInitCallTarget;

private:
    void parseLibcCsuInit();
    std::vector<Instruction> searchLibcCsuInit() const;
    void searchGadget2CallTarget(std::string funcName = "_fini");
    void buildRopPayloadTemplate() const;
    void invalidate() { m_isTemplateValid = false; }

    static inline bool hasExceeded32Bits(uint64_t value) {
        return value >= static_cast<uint64_t>(1) << 32;
    }


    uint64_t m_retAddr;
    uint64_t m_arg1;
    uint64_t m_arg2;
    uint64_t m_arg3;

    // Initialized in `Ret2csu::parseLibcCsuInit()`.
    uint64_t m_libcCsuInit;
    uint64_t m_libcCsuInitGadget1;
    uint64_t m_libcCsuInitGadget2;
    uint64_t m_libcCsuInitCallTarget;

    std::vector<std::string> m_gadget1Regs;
    std::map<std::string, std::string> m_gadget2Regs;
    std::string m_gadget2CallReg1;
    std::string m_gadget2CallReg2;

    // Rebuilding the entire ROP payload from scratch is expensive,
    // so we'll use a template as a cache, thereby declaring it mutable.
    mutable bool m_isTemplateValid;
    mutable std::vector<RopPayload> m_ropSubchainTemplate;
    mutable std::vector<Instruction> m_libcCsuInitInsns;
};

}  // namespace s2e::plugins::crax

#endif  // S2E_PLUGINS_CRAX_RET2CSU_H
