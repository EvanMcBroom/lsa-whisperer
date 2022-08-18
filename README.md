# MSV1_0 CLI

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat)](LICENSE.txt)

> Thank you to [Elad](https://twitter.com/elad_shamir) for providing the inspiration for this utility and the research, support, and collaboration throughout its development.

MSV1_0 CLI is a utility for interacting with the Microsoft Authentication Package v1.0 (MSV1_0).
The main goal of this project is to provide an easy utility for interacting with the additional functionality provided by MSV1_0.

The additional functionality that MSV1_0 supports is documented on MSDN and included here for convenience<sup>1</sup>:

| Id     | Message Type               | CLI Support        | NT Version   | Internal Function               |
| ---    | ---                        | ---                | ---          | ---                             |
| `0x00` | `Lm20ChallengeRequest`     | :x:                |              | `MspLm20Challenge`              |
| `0x01` | `Lm20GetChallengeResponse` | :x:                |              | `MspLm20GetChallengeResponse`   |
| `0x02` | `EnumerateUsers`           | :heavy_check_mark: | _All_        | `MspLm20EnumUsers`              |
| `0x03` | `GetUserInfo`              | :heavy_check_mark: | _All_        | `MspLm20GetUserInfo`            |
| `0x04` | `ReLogonUsers`             | :heavy_minus_sign: | _None_       | `MspLm20ReLogonUsers`           |
| `0x05` | `ChangePassword`           | :x:                |              | `MspLm20ChangePassword`         |
| `0x06` | `ChangeCachedPassword`     | _Planned_          | _All_        | `MspLm20ChangePassword`         |
| `0x07` | `GenericPassthrough`       | _Planned_          | _All_        | `MspLm20GenericPassthrough`     |
| `0x08` | `CacheLogon`               | :heavy_check_mark: | _All_        | `MspLm20CacheLogon`             |
| `0x09` | `SubAuth`                  | :x:                |              | `MspNtSubAuth`                  |
| `0x0A` | `DeriveCredential`         | :x:                |              | `MspNtDeriveCredential`         |
| `0x0B` | `CacheLookup`              | _Planned_          | _All_        | `MspLm20CacheLookup`            |
| `0x0C` | `SetProcessOption`         | :heavy_check_mark: | _All_        | `MspSetProcessOption`           |
| `0x0D` | `ConfigLocalAliases`       | :x:                |              | `MspConfigLocalAliases`         |
| `0x0E` | `ClearCachedCredentials`   | :heavy_check_mark: | `>=6.0`      | `MspLm20ClearCachedCredentials` |
| `0x0F` | `LookupToken`              | :x:                |              | `MspLookupToken`                |
| `0x10` | `ValidateAuth`             | :x:                |              | `MspValidateAuth`               |
| `0x11` | `CacheLookupEx`            | _Planned_          | `>=6.2`      | `MspLm20CacheLookup`            |
| `0x12` | `GetCredentialKey`         | _Planned_          | `>=6.2`      | `MspGetCredentialKey`           |
| `0x13` | `SetThreadOption`          | :x:                |              | `MspSetThreadOption`            |
| `0x14` | `DecryptDpapiMasterKey`    | _Planned_          | `>=6.4`      | `MspDecryptDpapiMasterKey`      |
| `0x15` | `GetStrongCredentialKey`   | _Planned_          | `>=6.4`      | `MspGetStrongCredentialKey`     |
| `0x16` | `TransferCred`             | _Planned_          | `>=10.0`     | `MspTransferCreds`              |
| `0x17` | `ProvisionTbal`            | :heavy_check_mark: | `>=10.0`     | `MspProvisionTbal`              |
| `0x18` | `DeleteTbalSecrets`        | :heavy_check_mark: | `>=10.0`     | `MspDeleteTbalSecrets`          |

> :pencil2: The internal function for each message type will be located in `msv1_0.dll`.

## Building

MSV1_0 CLI requres [cxxopts](https://github.com/jarro2783/cxxopts) and [magic_enum](https://github.com/Neargye/magic_enum) which can be installed using [vcpkg](https://github.com/microsoft/vcpkg).

```
vcpkg install cxxopts
vcpkg install magic_enum
```

MSV1_0 CLI uses [CMake](https://cmake.org/) to generate and run the build system files for your platform.

```
git clone https://github.com/EvanMcBroom/msv1_0-cli.git && cd msv1_0-cli
mkdir builds && cd builds
cmake ..
cmake --build .
```

MSV1_0 CLI will link against the static version of the runtime library which allows the tool to run as a standalone program on other hosts.

## Functions

- [CacheLogon](#CacheLogon)
- [CacheLookup](#CacheLookup)
- [CacheLookupEx](#CacheLookupEx)
- [ChangeCachedPassword](#ChangeCachedPassword)
- [ClearCachedCredentials](#ClearCachedCredentials)
- [DecryptDpapiMasterKey](#DecryptDpapiMasterKey)
- [DeleteTbalSecrets](#DeleteTbalSecrets)
- [EnumerateUsers](#EnumerateUsers)
- [GenericPassthrough](#GenericPassthrough)
- [GetCredentialKey](#GetCredentialKey)
- [GetStrongCredentialKey](#GetStrongCredentialKey)
- [GetUserInfo](#GetUserInfo)
- [ProvisionTbal](#ProvisionTbal)
- [SetProcessOption](#SetProcessOption)
- [TransferCred](#TransferCred)

### CacheLogon

This dispatch routine caches logon information in the logon cache.

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

Get the credential key of the authentication packet.
The `SeTcbPrivilege` is required.

```
msv1_0-cli.exe -f GetCredentialKey --luid {logon session}
```

### GetStrongCredentialKey

...

```
msv1_0-cli.exe -f GetStrongCredentialKey ...
```

### GetUserInfo

Get information about a logon id.

```
msv1_0-cli.exe -f GetUserInfo --luid {logon id}
```

### ProvisionTbal

Provision Trusted Boot Auto-Logon (TBAL) secrets for a logon session and store them in the System vault.<sup>2</sup>

```
msv1_0-cli.exe -f ProvisionTbal --luid {logon id}
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

### TransferCred

...

```
msv1_0-cli.exe -f TransferCred ...
```

## References

1. [MSV1_0_PROTOCOL_MESSAGE_TYPE enumeration (ntsecapi.h)](https://docs.microsoft.com/en-us/windows/win32/api/ntsecapi/ne-ntsecapi-msv1_0_protocol_message_type)
2. [What is Trusted Boot Auto-Logon (TBAL)?](https://www.passcape.com/index.php?section=blog&cmd=details&id=38#a6)