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

#ifndef S2E_PLUGINS_CRAX_ROP_GADGET_RESOLVER_H
#define S2E_PLUGINS_CRAX_ROP_GADGET_RESOLVER_H

#include <s2e/Plugins/CRAX/Pwnlib/ELF.h>

#include <map>
#include <mutex>
#include <string>

namespace s2e::plugins::crax {

class RopGadgetResolver {
public:
    RopGadgetResolver()
        : m_ropGadgetOutputCache(),
          m_ropGadgetCache() {}

    // Look for an exact match of the gadget specified by `gadgetAsm` within `elf`.
    // If found, then the offset of the gadget will be returned, and zero otherwise.
    uint64_t resolveGadget(const ELF &elf, const std::string &gadgetAsm) const;

private:
    // Resolving gadgets in libc.so.6 or some huge shared objects
    // can take a lot of time, so we use a cache to avoid repeated
    // gadget resolution. In addition, concurrent access from
    // different threads to this cache is safe.
    class RopGadgetCache {
    public:
        RopGadgetCache() : m_map(), m_mutex() {}

        void insert(const ELF *const elf, const std::string &gadgetAsm, uint64_t addr) {
            const std::lock_guard<std::recursive_mutex> lock(m_mutex);

            assert(!lookup(elf, gadgetAsm));
            m_map[std::make_pair(elf, gadgetAsm)] = addr;
        }

        uint64_t lookup(const ELF *const elf, const std::string &gadgetAsm) const {
            const std::lock_guard<std::recursive_mutex> lock(m_mutex);

            auto it = m_map.find(std::make_pair(elf, gadgetAsm));
            return it != m_map.end() ? it->second : 0;
        }

    private:
        using KeyType = std::pair<const ELF *, std::string>;
        using ValueType = uint64_t;

        std::map<KeyType, ValueType> m_map;
        mutable std::recursive_mutex m_mutex;
    };

    mutable std::map<const ELF *, std::string> m_ropGadgetOutputCache;
    mutable RopGadgetCache m_ropGadgetCache;
};

}  // namespace s2e::plugins::crax

#endif  // S2E_PLUGINS_CRAX_ROP_GADGET_RESOLVER_H
