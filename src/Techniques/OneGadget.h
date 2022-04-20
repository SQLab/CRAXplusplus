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

#ifndef S2E_PLUGINS_CRAX_ONE_GADGET_H
#define S2E_PLUGINS_CRAX_ONE_GADGET_H

#include <s2e/Plugins/CRAX/Techniques/Technique.h>

#include <regex>
#include <string>
#include <vector>

namespace s2e::plugins::crax {

class OneGadget : public Technique {
public:
    OneGadget();
    virtual ~OneGadget() override = default;

    virtual std::string toString() const override { return "OneGadget"; }

    virtual std::vector<RopPayload> getRopPayloadList() const override;
    virtual RopPayload getExtraRopPayload() const override { return {}; }

private:
    using GadgetValuePair = std::pair<std::string, klee::ref<klee::Expr>>;

    struct LibcOneGadget {
        LibcOneGadget() : offset(), gadgets() {}
        uint64_t offset;
        std::vector<GadgetValuePair> gadgets;
    };

    // Parses the output of `one_gadget <libc_path>` 
    std::vector<LibcOneGadget> parseOneGadget() const;

    // Parses a line of constraint and returns the gadget we need to resolve.
    // Input:  "r15 == NULL"
    // Output: ["pop r15 ; ret", r15_value]
    GadgetValuePair parseConstraint(const std::string &constraintStr) const;

    // The "one" gadget which will be used during the actual exploitation.
    LibcOneGadget m_oneGadget;
};

}  // namespace s2e::plugins::crax

#endif  // S2E_PLUGINS_CRAX_ONE_GADGET_H
