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

#ifndef S2E_PLUGINS_CRAX_GOT_PARTIAL_OVERWRITE_H
#define S2E_PLUGINS_CRAX_GOT_PARTIAL_OVERWRITE_H

#include <s2e/Plugins/CRAX/Techniques/Technique.h>

#include <string>
#include <vector>

namespace s2e::plugins::crax {

// Forward declaration
class CRAX;

class GotPartialOverwrite : public Technique {
public:
    explicit GotPartialOverwrite(CRAX &ctx);
    virtual ~GotPartialOverwrite() = default;

    virtual void initialize() override;
    virtual bool checkRequirements() const override;
    virtual void resolveRequiredGadgets() override;
    virtual std::string getAuxiliaryFunctions() const override;

    virtual std::vector<SymbolicRopPayload> getSymbolicRopPayloadList() const override;
    virtual ConcreteRopPayload getExtraPayload() const override;

    virtual std::string toString() const override;

private:
    uint8_t getLsbOfReadSyscall() const;
};

}  // namespace s2e::plugins::crax

#endif  // S2E_PLUGINS_CRAX_GOT_PARTIAL_OVERWRITE_H
