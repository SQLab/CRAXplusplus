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

#ifndef S2E_PLUGINS_CRAX_PROXY_H
#define S2E_PLUGINS_CRAX_PROXY_H

#include <s2e/Plugins/CRAX/Pwnlib/Process.h>

#include <string>
#include <vector>

namespace s2e::plugins::crax {

class Proxy {
public:
    enum class Type {
        NONE,
        SYM_ARG,
        SYM_ENV,
        SYM_FILE,
        SYM_SOCKET,
        SYM_STDIN,
        LAST
    };

    Proxy();

    std::string getConfigKey() const;
    void maybeDetectProxy(const std::string &imageFileName);

    Type getType() const { return m_type; }
    void setType(Type type) { m_type = type; }

    int getSocketFd() const { return m_socketFd; }
    bool isBlockingSocket() const { return m_isBlockingSocket; }

    // Proxy binary names.
    static const std::string s_symArg;
    static const std::string s_symEnv;
    static const std::string s_symFile;
    static const std::string s_symSocket;
    static const std::string s_symStdin;

private:
    void loadSymArgConfig();
    void loadSymEnvConfig();
    void loadSymFileConfig();
    void loadSymSocketConfig();
    void loadSymStdinConfig();

    Type m_type;

    // Proxy settings specific to sym_arg.

    // Proxy settings specific to sym_env.
    std::string m_payloadEnvKey;

    // Proxy settings specific to sym_file.

    // Proxy settings specific to sym_socket.
    std::string m_destAddr;
    int m_destPort;
    bool m_isTcp;
    int m_socketFd;
    bool m_isBlockingSocket;

    // Proxy settings specific to sym_stdin.

};

}  // namespace s2e::plugins::crax

#endif  // S2E_PLUGINS_CRAX_PROXY_H
