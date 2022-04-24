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

#ifndef S2E_PLUGINS_CRAX_RET2SYSCALL_H
#define S2E_PLUGINS_CRAX_RET2SYSCALL_H

#include <s2e/Plugins/CRAX/Techniques/Technique.h>

namespace s2e::plugins::crax {

class Ret2syscall : public Technique {
public:
    Ret2syscall();
    virtual ~Ret2syscall() override = default;

    virtual std::string toString() const override { return "Ret2syscall"; }

    virtual std::vector<RopPayload> getRopPayloadList() const override;
    virtual RopPayload getExtraRopPayload() const override { return {}; }

    ref<Expr> getSyscallGadget() const {
        return m_syscallGadget;
    }

    void setSyscallGadget(const ref<Expr> &syscallGadget) {
        m_syscallGadget = syscallGadget;
    }

private:
    enum class Strategy {
        UNDEFINED,
        STATIC_ROP,
        LIBC_ROP,
        GOT_HIJACKING_ROP,
    };

    std::vector<RopPayload> getRopPayloadListUsingStaticRop() const;
    std::vector<RopPayload> getRopPayloadListUsingLibcRop() const;
    std::vector<RopPayload> getRopPayloadListUsingGotHijackingRop() const;

    uint8_t getLibcReadSyscallOffsetLsb() const;

    // The location of the syscall gadget.
    ref<Expr> m_syscallGadget;

    Strategy m_strategy;
};

}  // namespace s2e::plugins::crax

#endif  // S2E_PLUGINS_CRAX_RET2SYSCALL_H
