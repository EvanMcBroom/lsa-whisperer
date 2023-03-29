# LSA Whisperer

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat)](LICENSE.txt)

> Thank you to [Elad](https://twitter.com/elad_shamir) for providing the inspiration for this tool and the research, support, and collaboration throughout its development.

LSA Whisperer is a set of tools for interacting with authentication packages using their individual message protocols.
The initial release of LSA Whisperer includes support for several msv1_0 messages.
Initial support is also provided for cloudap, negotiate, pku2u, schannel, and kerberos messages as well.
More authentication packages may be added in the future.

## Building

LSA Whisperer uses [CMake](https://cmake.org/) to generate and run the build system files for your platform.
The project does not rely on any library manager to allow it to be easily built in an offline environment if desired.

```
git clone --recurse-submodules https://github.com/EvanMcBroom/lsa-whisperer.git
cd lsa-whisperer/builds
cmake .. -A {Win32 | x64}
cmake --build .
```

By default CMake will build both the `lsa-whisperer` utility and the `sspi` static library it uses.
The `lsa-whisperer` utility will be linked against the static version of the runtime library which will allow the tool to run as a standalone program on other hosts.

If [Doxygen](https://www.doxygen.nl/) and the Python modules in the `docs/requirements.txt` file are installed, then CMake will build the documentation for the `sspi` static library as well.

## Open Source

Thank you to the following packages that are used in LSA Whisperer directly or indirectly:

- Cli
    - [AmokHuginnsson/replxx](https://github.com/AmokHuginnsson/replxx) (license - [Multiple](https://github.com/AmokHuginnsson/replxx/blob/master/LICENSE.md))
    - [Neargye/magic_enum](https://github.com/Neargye/magic_enum) (license - [MIT](https://github.com/Neargye/magic_enum/blob/master/LICENSE))
    - [jarro2783/cxxopts](https://github.com/jarro2783/cxxopts) (license - [MIT](https://github.com/jarro2783/cxxopts/blob/master/LICENSE))
- Docs
    - [Andrew-Chen-Wang/github-wiki-action](https://github.com/Andrew-Chen-Wang/github-wiki-action) (license - [Apache 2.0](https://github.com/Andrew-Chen-Wang/github-wiki-action/blob/master/LICENSE))
    - [breathe-doc/breathe](https://github.com/breathe-doc/breathe) (license - [BSD](https://github.com/breathe-doc/breathe/blob/master/LICENSE))
    - [doxygen/doxygen](https://github.com/doxygen/doxygen) (license - [GPL 2.0](https://github.com/doxygen/doxygen/blob/master/LICENSE))
    - [sphinx-doc/sphinx](https://github.com/sphinx-doc/sphinx) (license - [BSD](https://github.com/sphinx-doc/sphinx/blob/master/LICENSE))
    - [readthedocs/sphinx_rtd_theme](https://github.com/readthedocs/sphinx_rtd_theme) (license - [MIT](https://github.com/readthedocs/sphinx_rtd_theme/blob/master/LICENSE))

Thank you to the following related projects that greatly helped in the development of LSA Whisperer:

- [Kekeo](https://github.com/gentilkiwi/kekeo) - A little toolbox to play with Microsoft Kerberos in C
- [Impacket](https://github.com/SecureAuthCorp/impacket) - A collection of Python classes for working with network protocols
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) - A little tool to play with Windows security
- [NtObjectManager](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools/tree/main/NtObjectManager) - A library to access the NT object manager namespace
- [ROADtools](https://github.com/dirkjanm/ROADtools) - The Azure AD exploration framework
- [Rubeus](https://github.com/GhostPack/Rubeus) - A C# toolset for raw Kerberos interaction and abuses

## Acknowledgments

Aside from the creators and maintainers of the above [open source](#open) projects, additional thanks are needed to the following people who's research helped as well:

- [Adam Chester](https://twitter.com/_xpn_)
- [Lee Christensen](https://twitter.com/tifkin_)
- [Dr. Nestori Syynimaa](https://twitter.com/DrAzureAD)