# Third-party notices

## REA Safe Agent

`reverseai/intake.py` ports the input-snapshot safeguards of REA Safe Agent
(https://github.com/dagoSte/rea-safe-agents), file
`skills/rea-isolated/scripts/input_snapshot.py` at committed revision
`c6f45cd27f1ed8ca774d5438d86d4b4f81c484fe`. That code is distributed under the
following license:

```text
MIT License

Copyright (c) 2026 Stefano D'Agostino

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## REA Safe Agent: Ghidra build approach

`containers/ghidra/Dockerfile` follows the Ghidra build of REA Safe Agent's
`skills/rea-isolated/assets/Dockerfile` at committed revision
`c6f45cd27f1ed8ca774d5438d86d4b4f81c484fe`: the same pinned Ghidra 12.1.4 and Temurin
JDK 21.0.12.1+1 inputs, and the commands that build the arm64 decompiler (`make
ghidra_opt ARCH_TYPE= OSDIR=linux_arm_64`) and the GNU demangler from the release's
own sources. That file is distributed under the MIT License reproduced above
(Copyright (c) 2026 Stefano D'Agostino).

## Ghidra and the Temurin JDK (Ghidra worker image only)

The locally built image `reverseai-ghidra` (`tools/build_ghidra_image.py`, decision
`owner-m3-downloads`) contains Ghidra 12.1.4 from the National Security Agency
(`ghidra_12.1.4_PUBLIC_20260921.zip`, SHA-256
`ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db`), licensed under the
Apache License 2.0, with the third-party components and licenses listed inside that
release (its `licenses/` and `GPL/` folders; the arm64 decompiler and GNU demangler are
built from its sources), and the Eclipse Temurin JDK 21.0.12.1+1 for aarch64
(SHA-256 `23e37e026f12f3e706f18938ff611db3032d075b09d0879a25d06718c773e223`), licensed
under the GNU General Public License version 2 with the Classpath Exception. Debian's
`g++` 4:14.2.0-1 and `make` 4.4.1-2 are used only in the image's build stage (decision
`owner-m3-apt-trixie`) and are not part of the image. This repository does not
redistribute any of these files.
