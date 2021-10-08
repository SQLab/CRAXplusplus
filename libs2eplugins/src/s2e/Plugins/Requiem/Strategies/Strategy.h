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

#ifndef S2E_PLUGINS_REQUIEM_STRATEGY_H
#define S2E_PLUGINS_REQUIEM_STRATEGY_H

#include <s2e/Plugins/Requiem/Techniques/Technique.h>

#include <memory>
#include <vector>

namespace s2e::plugins::requiem {

// Forward declaration
class Requiem;

// The base class for all exploitation strategy.
class Strategy {
public:
    void addAuxiliaryTechnique(std::unique_ptr<Technique> t) {
        m_auxiliaryTechniques.push_back(std::move(t));
    }

    void addPrimaryTechnique(std::unique_ptr<Technique> t) {
        m_primaryTechniques.push_back(std::move(t));
    }

    const std::vector<std::unique_ptr<Technique>> &getAuxiliaryTechniques() const {
        return m_auxiliaryTechniques;
    }

    const std::vector<std::unique_ptr<Technique>> &getPrimaryTechniques() const {
        return m_primaryTechniques;
    }

protected:
    // Mark the constructor protected so that
    // it becomes an abstract base class.
    Strategy(Requiem &ctx) : m_ctx(ctx) {}

    // Requiem's attributes.
    Requiem &m_ctx;

private:
    std::vector<std::unique_ptr<Technique>> m_auxiliaryTechniques;
    std::vector<std::unique_ptr<Technique>> m_primaryTechniques;
};

}  // namespace s2e::plugins::requiem

#endif  // S2E_PLUGINS_REQUIEM_STRATEGY_H
