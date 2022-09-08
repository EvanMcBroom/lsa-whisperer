# LSA Whisperer

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat)](LICENSE.txt)

> Thank you to [Elad](https://twitter.com/elad_shamir) for providing the inspiration for these tools and the research, support, and collaboration throughout their development.

LSA Whisperer is a set of tools for interacting with authentication packages using their individual message protocols.
The initial release of LSA Whisperer includes support for the Microsoft Authentication Package v1.0 (MSV1_0).
More authentication packages may be added in the future.


The LSA Whisperer project provides the following tools for interacting with MSV1_0:

- `msv1_0-cli` - An interactive CLI for MSV1_0
- `msv1_0-dotnet` -  A .NET assembly equivalent to `msv1_0-cli`
- `pymsv1_0` - A python module for interacting with MSV1_0

The protocol messages that MSV1_0 supports is documented on MSDN and included here for convenience<sup>1</sup>:

| Id     | Message Type               | CLI Support        | NT Version   | Internal Function               |
| ---    | ---                        | ---                | ---          | ---                             |
| `0x00` | `Lm20ChallengeRequest`     | :heavy_check_mark: | _All_        | `MspLm20Challenge`              |
| `0x01` | `Lm20GetChallengeResponse` | :x:                |              | `MspLm20GetChallengeResponse`   |
| `0x02` | `EnumerateUsers`           | :heavy_check_mark: | _All_        | `MspLm20EnumUsers`              |
| `0x03` | `GetUserInfo`              | :heavy_check_mark: | _All_        | `MspLm20GetUserInfo`            |
| `0x04` | `ReLogonUsers`             | :heavy_minus_sign: | _None_       | `MspLm20ReLogonUsers`           |
| `0x05` | `ChangePassword`           | :x:                |              | `MspLm20ChangePassword`         |
| `0x06` | `ChangeCachedPassword`     | _Planned_          | _All_        | `MspLm20ChangePassword`         |
| `0x07` | `GenericPassthrough`       | _Planned_          | _All_        | `MspLm20GenericPassthrough`     |
| `0x08` | `CacheLogon`               | :heavy_check_mark: | _All_        | `MspLm20CacheLogon`             |
| `0x09` | `SubAuth`                  | :x:                |              | `MspNtSubAuth`                  |
| `0x0A` | `DeriveCredential`         | :heavy_check_mark: | _All_        | `MspNtDeriveCredential`         |
| `0x0B` | `CacheLookup`              | _Planned_          | _All_        | `MspLm20CacheLookup`            |
| `0x0C` | `SetProcessOption`         | :heavy_check_mark: | _All_        | `MspSetProcessOption`           |
| `0x0D` | `ConfigLocalAliases`       | :x:                |              | `MspConfigLocalAliases`         |
| `0x0E` | `ClearCachedCredentials`   | :heavy_check_mark: | `>=6.0`      | `MspLm20ClearCachedCredentials` |
| `0x0F` | `LookupToken`              | :x:                |              | `MspLookupToken`                |
| `0x10` | `ValidateAuth`             | :x:                |              | `MspValidateAuth`               |
| `0x11` | `CacheLookupEx`            | _Planned_          | `>=6.2`      | `MspLm20CacheLookup`            |
| `0x12` | `GetCredentialKey`         | :heavy_check_mark: | `>=6.2`      | `MspGetCredentialKey`           |
| `0x13` | `SetThreadOption`          | :x:                |              | `MspSetThreadOption`            |
| `0x14` | `DecryptDpapiMasterKey`    | _Planned_          | `>=6.4`      | `MspDecryptDpapiMasterKey`      |
| `0x15` | `GetStrongCredentialKey`   | _Planned_          | `>=6.4`      | `MspGetStrongCredentialKey`     |
| `0x16` | `TransferCred`             | :heavy_check_mark: | `>=10.0`     | `MspTransferCreds`              |
| `0x17` | `ProvisionTbal`            | :heavy_check_mark: | `>=10.0`     | `MspProvisionTbal`              |
| `0x18` | `DeleteTbalSecrets`        | :heavy_check_mark: | `>=10.0`     | `MspDeleteTbalSecrets`          |

> :pencil2: The internal function for each message type will be located in `msv1_0.dll`.

## Building

LSA Whisperer requres [cxxopts](https://github.com/jarro2783/cxxopts) and [magic_enum](https://github.com/Neargye/magic_enum) which can both be installed using [vcpkg](https://github.com/microsoft/vcpkg).

```cmd
vcpkg install cxxopts:x64-windows-static
vcpkg install magic-enum:x64-windows-static
rem Optional install
vcpkg install pybind11:x64-windows
```

You may optionally install [pybind11](https://github.com/pybind/pybind11) for `pymsv1_0` to be built as well.
If you choose to build `pymsv1_0`, you will need to ensure that the Python debug binaries have been installed on your host.

LSA Whisperer uses [CMake](https://cmake.org/) to generate and run the build system files for your platform.

```
git clone https://github.com/EvanMcBroom/msv1_0-cli.git && cd msv1_0-cli
mkdir builds && cd builds
cmake .. -DCMAKE_TOOLCHAIN_FILE=PATH_TO_VCPKG\scripts\buildsystems\vcpkg.cmake
cmake --build .
```

The `msv1_0-cli` utility will link against the static version of the runtime library which allows the tool to run as a standalone program on other hosts.

## Functions

- [CacheLogon](#CacheLogon)
- [CacheLookup](#CacheLookup)
- [CacheLookupEx](#CacheLookupEx)
- [ChangeCachedPassword](#ChangeCachedPassword)
- [ChangePassword](#ChangePassword)
- [ClearCachedCredentials](#ClearCachedCredentials)
- [DecryptDpapiMasterKey](#DecryptDpapiMasterKey)
- [DeleteTbalSecrets](#DeleteTbalSecrets)
- [DeriveCredential](#DeriveCredential)
- [EnumerateUsers](#EnumerateUsers)
- [GenericPassthrough](#GenericPassthrough)
- [GetCredentialKey](#GetCredentialKey)
- [GetStrongCredentialKey](#GetStrongCredentialKey)
- [GetUserInfo](#GetUserInfo)
- [Lm20ChallengeRequest](#Lm20ChallengeRequest)
- [ProvisionTbal](#ProvisionTbal)
- [SetProcessOption](#SetProcessOption)
- [SetThreadOption](#SetThreadOption)
- [TransferCred](#TransferCred)

### CacheLogon

This dispatch routine caches logon information in the logon cache.
MSV1_0 will check to make sure the client request came from the same process.

```
msv1_0-cli.exe -f CacheLogon --domain {name} --account {name} [--computer name] {--hash {value} | --pass {value}} [--mitlogon {upn}] [--suppcreds {data}] [--delete] [--smartcard]
```

### CacheLookup

...
For a cached smart card logon the issuer and subject name will be used as the user name and domain name, the credential type will be raw, and the credential data will be the SHA1 hash of the certificate.

```
msv1_0-cli.exe -f CacheLookup --account {name} [--domain name] --credtype {name} --cred {ascii hex}
```

### CacheLookupEx

This dispatch routine looks up the local logon in the cache.
The `SeTcbPrivilege` is required.

```
msv1_0-cli.exe -f CacheLookupEx ...
```

### ChangeCachedPassword

This dispatch routine changes a password in the logon cache.
This is used when the password is changed on the domain controller using some other mechanism and the locally cached version needs to be updated to match the new value.
For example, RAS handles changing the passwords on the domain but then needs to update the cached copy so the user can still access servers.
The `SeTcbPrivilege` is required if you are changing the cached entry for someone else.

```
msv1_0-cli.exe -f ChangeCachedPassword --domain {name} --account {name} --oldpass {password} --newpass {password}
```

## ChangePassword

Not implemented.
Appears at first to be coercible, but LSASS will impersonate itself and remove the admin (`S-1-5-32-544`) sid before making a connection to another computer.

### ClearCachedCredentials

Clear the credentials in the local NTLM logon cache.
The `SeTcbPrivilege` is required.

```
msv1_0-cli.exe -f ClearCachedCredentials
```

### DecryptDpapiMasterKey

...

```
msv1_0-cli.exe -f DecryptDpapiMasterKey ...
```

### DeleteTbalSecrets

Clear the Trusted Boot Auto-Logon (TBAL) secrets in the System vault.<sup>2</sup>

```
msv1_0-cli.exe -f DeleteTbalSecrets
```

## DeriveCredential

Get the [SHA1 HMAC](https://en.wikipedia.org/wiki/HMAC) for a provided message using an NT OWF or SHA1 OWF password as the key, specified by the logon session id.
The `--sha1v2` argument specifies to use the SHA1 OWF password instead of the NT OWF password.
The `SeTcbPrivilege` may be required when specifying an id for another logon session but still need to verify that.

```
msv1_0-cli.exe -f DeriveCredential --luid {session id} [--sha1v2] --message {ascii hex}
```

### EnumerateUsers

Enumerates all interactive, service, and batch logons managed by MSV1_0.
The machine account logon will not be included in the list.

```
msv1_0-cli.exe -f EnumerateUsers
```

### GenericPassthrough

This dispatch routine passes any of the other dispatch routines to the domain controller.
The authentication package on the domain controller may choose to reject certain dispatch requests.

```
msv1_0-cli.exe -d -f {function name} [function arguments]...
```

### GetCredentialKey

Get the primary credential keys for a logon session.
The keys will either be the NT and SHA OWF hashes or the SHA hash and the DPAPI key.
The `SeTcbPrivilege` is required and credential isolation must also not be enabled.

```
msv1_0-cli.exe -f GetCredentialKey --luid {session id}
```

### GetStrongCredentialKey

...

```
msv1_0-cli.exe -f GetStrongCredentialKey ...
```

### GetUserInfo

Get information about a session id.

```
msv1_0-cli.exe -f GetUserInfo --luid {session id}
```

### Lm20ChallengeRequest

Get a challenge that may be delivered to a host that initiated an NTLMv2 logon.
Once a challenge response is received, it may be passed to `LsaLogonUser` with a `LogonType` of `MsV1_0Lm20Logon` to complete the logon.

```
msv1_0-cli.exe -f Lm20ChallengeRequest
```

### ProvisionTbal

Provision the Trusted Boot Auto-Logon (TBAL) LSA secrets for a logon session.<sup>2</sup>
The host is required to be actively kernel debugged for the function to succeed.

```
msv1_0-cli.exe -f ProvisionTbal --luid {session id}
```

### SetProcessOption

Enable or disable an option for the calling process.
The `SeTcbPrivilege` is required.
The currently known set of process options include:

- `AllowBlankPassword`
- `AllowOldPassword`
- `DisableAdminLockout`
- `DisableForceGuest`
- `TryCacheFirst`

MSV1_0 may internally check for one these options using `NtLmCheckProcessOption`.

```
msv1_0-cli.exe -f SetProcessOption --option {process option} [--disable]
```

## SetThreadOption

Enable or disable an option for the calling thread.
The set of options are the same as with the `SetProcessOption` command but they will take precedence over process options.
The `SeTcbPrivilege` is required.

```
msv1_0-cli.exe -f SetThreadOption --option {thread option} [--disable]
```

### TransferCred

Transfer data from one logon session to another logon session.
The specific data that is transferred and privileges that may be required are still being determined.

```
msv1_0-cli.exe -f TransferCred --sluid {session id} --dluid {session id}
```

## References

1. [MSV1_0_PROTOCOL_MESSAGE_TYPE enumeration (ntsecapi.h)](https://docs.microsoft.com/en-us/windows/win32/api/ntsecapi/ne-ntsecapi-msv1_0_protocol_message_type)
2. [What is Trusted Boot Auto-Logon (TBAL)?](https://www.passcape.com/index.php?section=blog&cmd=details&id=38#a6)