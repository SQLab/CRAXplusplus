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

#ifndef S2E_PLUGINS_CRAX_TECHNIQUE_H
#define S2E_PLUGINS_CRAX_TECHNIQUE_H

#include <s2e/Plugins/CRAX/Expr/Expr.h>

#include <map>
#include <memory>
#include <string>
#include <vector>

namespace s2e::plugins::crax {

using RopSubchain = std::vector<klee::ref<klee::Expr>>;

// The abstract base class of all concrete exploitation techniques,
// e.g., stack pivoting, ret2csu, orw, etc.
class Technique {
public:
    Technique() = default;
    virtual ~Technique() = default;

    virtual void initialize() = 0;
    virtual bool checkRequirements() const = 0;
    virtual void resolveRequiredGadgets() = 0;
    virtual std::string toString() const = 0;

    virtual std::vector<RopSubchain> getRopSubchains() const = 0;
    virtual RopSubchain getExtraRopSubchain() const = 0;

    static std::unique_ptr<Technique> create(const std::string &name);
    static std::map<std::string, Technique*> s_mapper;
};

}  // namespace s2e::plugins::crax

#endif  // S2E_PLUGINS_CRAX_TECHNIQUE_H
