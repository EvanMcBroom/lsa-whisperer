# LSA Whisperer

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat)](LICENSE.txt)
[![Bloodhound Slack](https://img.shields.io/badge/BloodHound%20Slack-4A154B?logo=slack&logoColor=white)](https://ghst.ly/BHSlack)
[![Sponsored by SpecterOps](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/specterops/.github/main/config/shield.json)](https://github.com/specterops)

LSA Whisperer is a set of tools for interacting with authentication packages using their individual message protocols.
You may download prebuilt copies of LSA Whisperer from the assets section of its [latest release](https://github.com/EvanMcBroom/lsa-whisperer/releases/tag/latest).

Support is currently provided for the cloudap, kerberos, msv1_0, negotiate, pku2u, and schannel packages and cloudap's AzureAD plugin.
Partial or unstable support is provided for livessp, negoexts, and the security package manager (SPM).
Please refer to the [wiki](https://github.com/EvanMcBroom/lsa-whisperer/wiki) to see which message protocols are currently supported. 

Support for more authentication packages and package calls may be added in the future.
If you are interested in a package call that is not implemented or you see an area of the wiki that can be improved, please submit an issue on GitHub or consider making a pull request (PR) for the project.
Contributions are appreciated!

## Building

LSA Whisperer uses [CMake](https://cmake.org/) to generate and run the build system files for your platform.
The project does not rely on any library manager to allow it to be easily built in an offline environment if desired.
You will need [the latest Windows 11 SDK](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/), which at the time of this writing is 10.0.22621.0.

```
git clone --recurse-submodules https://github.com/EvanMcBroom/lsa-whisperer.git
cd lsa-whisperer/builds
cmake .. -A {Win32 | x64}
cmake --build .
```

> :pencil2: If you have an issue building the project, please check the output of the generation step (e.g., `cmake ..`) to ensure that cmake chose the correct Windows SDK version.
If you have multiple Windows SDKs installed, you will likely need to remove all files in the `builds` folder then rerun the generation step while specifying the correct version for cmake to use (e.g., `cmake .. -DCMAKE_SYSTEM_VERSION=10.0.22621.0`).

By default CMake will build both the `lsa-whisperer` utility and the `sspi` static library it uses.
The `lsa-whisperer` utility will be linked against the static version of the runtime library which will allow the tool to run as a standalone program on other hosts.

If [Doxygen](https://www.doxygen.nl/) and the Python modules in the `docs/requirements.txt` file are installed, then CMake will build the documentation for the `sspi` static library as well.

## Open Source

Thank you to the following packages that are used in LSA Whisperer directly or indirectly:

- Cli
    - [AmokHuginnsson/replxx](https://github.com/AmokHuginnsson/replxx) (license - [Multiple](https://github.com/AmokHuginnsson/replxx/blob/master/LICENSE.md))
    - [jarro2783/cxxopts](https://github.com/jarro2783/cxxopts) (license - [MIT](https://github.com/jarro2783/cxxopts/blob/master/LICENSE))
    - [muellan/clipp](https://github.com/muellan/clipp) (license - [MIT](https://github.com/muellan/clipp/blob/master/LICENSE))
    - [Neargye/magic_enum](https://github.com/Neargye/magic_enum) (license - [MIT](https://github.com/Neargye/magic_enum/blob/master/LICENSE))

- Docs
    - [Andrew-Chen-Wang/github-wiki-action](https://github.com/Andrew-Chen-Wang/github-wiki-action) (license - [Apache 2.0](https://github.com/Andrew-Chen-Wang/github-wiki-action/blob/master/LICENSE))
    - [breathe-doc/breathe](https://github.com/breathe-doc/breathe) (license - [BSD](https://github.com/breathe-doc/breathe/blob/master/LICENSE))
    - [doxygen/doxygen](https://github.com/doxygen/doxygen) (license - [GPL 2.0](https://github.com/doxygen/doxygen/blob/master/LICENSE))
    - [readthedocs/sphinx_rtd_theme](https://github.com/readthedocs/sphinx_rtd_theme) (license - [MIT](https://github.com/readthedocs/sphinx_rtd_theme/blob/master/LICENSE))
    - [sphinx-doc/sphinx](https://github.com/sphinx-doc/sphinx) (license - [BSD](https://github.com/sphinx-doc/sphinx/blob/master/LICENSE))

Although not used by LSA Whisperer, the following projects greatly helped in its development:

- [Impacket](https://github.com/SecureAuthCorp/impacket) ([Alberto Solino](https://twitter.com/agsolino)) - A collection of Python classes for working with network protocols
- [Kekeo](https://github.com/gentilkiwi/kekeo) ([Benjamin Delpy](https://twitter.com/gentilkiwi)) - A little toolbox to play with Microsoft Kerberos in C
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) ([Benjamin Delpy](https://twitter.com/gentilkiwi)) - A little tool to play with Windows security
- [NtObjectManager](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools/tree/main/NtObjectManager) ([James Forshaw](https://twitter.com/tiraniddo)) - A library to access the NT object manager namespace
- [ROADtools](https://github.com/dirkjanm/ROADtools) ([Dirk-jan Mollema](https://twitter.com/_dirkjan)) - The Azure AD exploration framework
- [Rubeus](https://github.com/GhostPack/Rubeus) ([Will Schroeder](https://twitter.com/harmj0y), [Charlie Clark](https://twitter.com/exploitph)) - A C# toolset for raw Kerberos interaction and abuses

## Acknowledgments

Thank you to [SpecterOps](https://specterops.io/) for supporting this research and to my coworkers who have helped with its development.

Thank you [Elad](https://twitter.com/elad_shamir) and [Lee](https://twitter.com/tifkin_) for both inspiring this tool and the research, support, and collaboration throughout its development.
Elad additionally developed operational use cases for [msv1_0](https://github.com/EvanMcBroom/lsa-whisperer/wiki/msv1_0) and Lee both introduced me to [cloudap](https://github.com/EvanMcBroom/lsa-whisperer/wiki/cloudap) and showed it's potential for recovering authentication data.
Thank you as well to [Will](https://twitter.com/harmj0y) for always being a good sounding board and helping test the tool, [Daniel](https://twitter.com/hotnops) for answering my AzureAD questions, and [Kai](https://twitter.com/mhskai2017) for helping both research [cloudap](https://github.com/EvanMcBroom/lsa-whisperer/wiki/cloudap) and add Kerberos support.

## Related Work

- [Adam Chester](https://twitter.com/_xpn_) ([2019](https://blog.xpnsec.com/exploring-mimikatz-part-2/)), showed a POC for SPM's AddPackage API
- [Alex Short](https://twitter.com/alexsho71327477) ([2023](https://github.com/rbmm/TBAL)), showed POCs for ARSO and TBAL
- [Mor Rubin](https://twitter.com/rubin_mor) ([2020](https://medium.com/@mor2464/azure-ad-pass-the-certificate-d0c5de624597)), created tools and techniques for NegoEX
- [Dr. Nestori Syynimaa](https://twitter.com/DrAzureAD) ([2017-Current](https://aadinternals.com/post/welcome/)), for the Office 365 blog
- [Passcape Software](https://www.passcape.com/) ([2019](https://www.passcape.com/text/articles/tbal.pdf)), documented ARSO and TBAL
- [Steve Syfuhs](https://twitter.com/SteveSyfuhs) ([2017-Current](https://syfuhs.net/category/Authentication)), for the Windows Authentication blog posts
