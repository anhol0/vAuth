# Third-party software notices

vAuth uses the third-party libraries listed below. They are not covered by
vAuth's MIT license. Each library remains subject to its own copyright and
license terms.

The vAuth source tree does not vendor these libraries. Normal Linux packages
link against separately installed shared libraries, except that CLI11 and
nlohmann/json are header-only dependencies whose code is compiled into vAuth.
A distributor that bundles or statically links a dependency must verify the
exact version it ships and include that version's complete license, notices,
and corresponding source or relinking material where its license requires them.

This file covers direct library dependencies. The operating-system packages
that provide them may have additional, separately licensed dependencies.

## CLI11

- Project: [CLI11](https://github.com/CLIUtils/CLI11)
- License: [BSD 3-Clause](https://github.com/CLIUtils/CLI11/blob/main/LICENSE)
- Copyright: Copyright (c) 2017-2026 University of Cincinnati, developed by
  Henry Schreiner under NSF Award 1414736. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
3. Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

## JSON for Modern C++

- Project: [nlohmann/json](https://github.com/nlohmann/json)
- License: [MIT](https://github.com/nlohmann/json/blob/develop/LICENSE.MIT)
- Copyright: Copyright (c) 2013-2026 Niels Lohmann.

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## TinyCBOR

- Project: [TinyCBOR](https://github.com/intel/tinycbor)
- License: [MIT](https://github.com/intel/tinycbor/blob/master/LICENSE)
- Copyright: Copyright (c) 2015-2018, 2021 Intel Corporation; copyright
  (c) 2019 S. Phirsov.

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## OpenSSL

- Project: [OpenSSL](https://www.openssl.org/)
- License: [Apache License 2.0](https://github.com/openssl/openssl/blob/master/LICENSE.txt)
- Copyright: The OpenSSL Project Authors and other contributors identified in
  the OpenSSL source distribution.

OpenSSL 3.x is licensed under Apache-2.0. Distributions that include OpenSSL
must include its complete license and retain any applicable notices from the
exact OpenSSL release being shipped.

## TPM2 Software Stack

- Project: [TPM2-TSS](https://github.com/tpm2-software/tpm2-tss)
- License: [BSD 2-Clause](https://github.com/tpm2-software/tpm2-tss/blob/master/LICENSE)
- Copyright: Copyright (c) 2015 Intel Corporation and the TPM2-TSS
  contributors.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

## Linux-PAM

- Project: [Linux-PAM](https://github.com/linux-pam/linux-pam)
- License: [BSD-style terms or GPL](https://github.com/linux-pam/linux-pam/blob/master/Copyright)
- Copyright: The Linux-PAM authors and contributors identified in the
  Linux-PAM `Copyright` and source files.

vAuth uses Linux-PAM under its BSD-style alternative. Binary redistributions
of Linux-PAM must reproduce its prior and current copyright notices, permission
conditions, and warranty disclaimer. The exact upstream `Copyright` file is
the authoritative notice and must accompany Linux-PAM when it is bundled.

## sdbus-c++

- Project: [sdbus-c++](https://github.com/Kistler-Group/sdbus-cpp)
- License: GNU Lesser General Public License 2.1 or later, with the upstream
  exception for macros, templates, and inline functions in public headers
- Copyright: Copyright (c) 2016-2017 Kistler Instrumente AG; copyright
  (c) 2016-2019 Stanislav Angelovic.

The license and header exception are distributed in the
[sdbus-c++ repository](https://github.com/Kistler-Group/sdbus-cpp). vAuth uses
the shared-library interface.

## systemd and libsystemd

- Project: [systemd](https://github.com/systemd/systemd)
- License: [GNU Lesser General Public License 2.1 or later](https://github.com/systemd/systemd/blob/main/LICENSES/README.md)
- Copyright: The systemd authors and contributors identified in the systemd
  source files and distribution notices.

vAuth links to `libsystemd` and invokes systemd tools. It does not incorporate
the separately licensed systemd executables.

## Slint

- Project: [Slint](https://slint.dev/)
- License selected for `vauth-ui`: [Slint Royalty-free Desktop, Mobile, and
  Web Applications License 2.0](https://github.com/slint-ui/slint/blob/master/LICENSES/LicenseRef-Slint-Royalty-free-2.0.md)
- Copyright: Copyright (c) SixtyFPS GmbH and the Slint contributors.

That license requires either the `AboutSlint` widget in the application or a
readily discoverable Slint attribution badge on a public webpage. The vAuth
README displays and links the Slint badge. This selection applies to vAuth's
Linux desktop UI; it does not grant rights to use Slint in an embedded product.

Slint is also available under GPL-3.0-only and a commercial license. A
distributor choosing one of those alternatives must comply with that license
instead.

## rlottie

- Project: [rlottie](https://github.com/Samsung/rlottie)
- Copyright: Copyright (c) 2018 Samsung Electronics Co., Ltd. All rights
  reserved.

rlottie's license depends on the release. Version 0.1 packages, including the
Debian 0.1 package, are distributed under LGPL-2.1-or-later. Upstream release
0.2 changed the main project license to MIT. A vAuth binary distributor must
record which rlottie release it uses and include that release's `COPYING` file
and any notices for code included in that build.

The rlottie library license does not cover the Lottie animation documents in
`client/assets/`; those assets require separate author and license provenance.
