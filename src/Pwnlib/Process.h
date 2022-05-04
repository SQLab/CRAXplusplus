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

#ifndef S2E_PLUGINS_CRAX_PROCESS_H
#define S2E_PLUGINS_CRAX_PROCESS_H

#include <map>
#include <string>
#include <vector>

namespace s2e::plugins::crax {

class Process {
public:
    using Argv = std::vector<std::string>;
    using Env = std::map<std::string, std::string>;

    Process(const std::string &ldFilename,
            const std::string &elfFilename,
            const std::string &libcFilename);

    // Get a decl statement. This is used for exploit script generation.
    // e.g., "proc = process(...)"
    std::string toDeclStmt() const;

    Argv &getArgv() { return m_argv; }
    Env &getEnv() { return m_env; }
    bool isAslrEnabled() const { return m_isAslrEnabled; }
    void setAslrEnabled(bool enabled) { m_isAslrEnabled = enabled; }

private:
    Argv createDefaultArgv(const std::string &ldFilename,
                           const std::string &elfFilename) const;

    Env createDefaultEnv(const std::string &libcFilename) const;

    std::string argvToString() const;
    std::string envToString() const;

    Argv m_argv;
    Env m_env;
    bool m_isAslrEnabled;
};

}  // namespace s2e::plugins::crax

#endif  // S2E_PLUGINS_CRAX_PROCESS_H
