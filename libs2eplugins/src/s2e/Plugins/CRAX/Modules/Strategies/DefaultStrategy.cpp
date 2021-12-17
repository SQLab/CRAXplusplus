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
#include <s2e/Plugins/CRAX/Modules/Techniques/Ret2csu.h>
#include <s2e/Plugins/CRAX/Modules/Techniques/StackPivot.h>
#include <s2e/Plugins/CRAX/Modules/Techniques/GotPartialOverwrite.h>

#include <memory>

#include "DefaultStrategy.h"

namespace s2e::plugins::crax {

DefaultStrategy::DefaultStrategy(CRAX &ctx) : Strategy(ctx) {
    // Register auxiliary techniques>
    addAuxiliaryTechnique(std::make_unique<Ret2csu>(ctx));

    // Register primary techniques.
    addPrimaryTechnique(std::make_unique<BasicStackPivot>(ctx));
    //addPrimaryTechnique(std::make_unique<AdvancedStackPivot>(ctx));
    addPrimaryTechnique(std::make_unique<GotPartialOverwrite>(ctx));

    /*
    addPrimaryTechnique(
            std::make_unique<Ret2csu>(ctx,
                                      "0xdeadbeefdeadbeef",
                                      "0xcafebabecafebabe",
                                      "0xd00df00dd00df00d",
                                      "elf.sym['ret2win']"));
    */
}

}  // namespace s2e::plugins::crax