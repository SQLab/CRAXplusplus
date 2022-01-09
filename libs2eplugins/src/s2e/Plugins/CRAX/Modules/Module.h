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

#ifndef S2E_PLUGINS_CRAX_MODULE_H
#define S2E_PLUGINS_CRAX_MODULE_H

#include <memory>
#include <map>
#include <string>

namespace s2e::plugins::crax {

// Forward declaration
class CRAX;
class CRAXState;
class Module;
class ModuleState;

using ModuleStateFactory = ModuleState *(*)(Module *, CRAXState *);

// The abstract base class of all modules.
//
// The concept of "modules" in CRAX is similar to that of "plugins" in S2E.
// Essentially, a module is an S2E-plugin's plugin.
class Module {
public:
    explicit Module(CRAX &ctx) : m_ctx(ctx) {}
    virtual ~Module() = default;

    virtual std::string toString() const = 0;

    ModuleState *getModuleState(CRAXState *state, ModuleStateFactory f) const;

    static std::unique_ptr<Module> create(CRAX &ctx, const std::string &name);

    static std::map<std::string, Module *> s_mapper;

protected:
    CRAX &m_ctx;
};


// The per-state information of a CRAX's module.
class ModuleState {
public:
    virtual ~ModuleState() = default;
    virtual ModuleState *clone() const = 0;

    static ModuleState *factory(Module *, CRAXState *);
};

}  // namespace s2e::plugins::crax

#endif  // S2E_PLUGINS_CRAX_MODULE_H
