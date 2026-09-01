# KeePassCredential

KeePass-backed `PSCredential` objects for PowerShell 7 — for `Enter-PSSession`, `Invoke-Command`, or anything else that takes `-Credential`.

```powershell
Enter-PSSession -ComputerName SRV-APP01 -Credential (Get-KpCredential SRV-APP01)
Copy-KpPassword 'SRV-APP01'
```

## Why a bridge

KeePass 2.x is a .NET Framework assembly, so `KeePassLib` only loads in **Windows PowerShell 5.1** — under `pwsh` it dies on `Could not load type 'System.Security.Cryptography.ProtectedMemory'`. But your interactive shell is pwsh 7, and `Enter-PSSession` has to run there.

So this module shells out to 5.1 to read the entry and brings the password back as a **DPAPI blob** (CurrentUser scope) that only the calling Windows account can decrypt. Plaintext never crosses the process boundary — not on stdout, not on a command line, not in an environment variable.

> The 5.1 child inherits pwsh 7's `PSModulePath`, which makes it resolve `Microsoft.PowerShell.Security` to the 7.x copy and fail to import with a type-data collision. `_KpBridge.ps1` resets `PSModulePath` before touching any module. Don't remove that.

## Requirements

- Windows, PowerShell 7+
- KeePass 2.x installed (default path `C:\Program Files\KeePass Password Safe 2\KeePass.exe`)
- Windows PowerShell 5.1 (ships with Windows)

## Install

There is no native "install from GitHub" in PowerShell — `Install-Module` only talks to PSGallery-style NuGet feeds. Clone into `PSModulePath` and `git pull` to update.

**Clone directly into the modules folder:**

```powershell
git clone https://github.com/<you>/KeePassCredential.git `
    "$HOME\Documents\PowerShell\Modules\KeePassCredential"
```

**Or keep it with your other repos and link it:**

```powershell
git clone https://github.com/<you>/KeePassCredential.git D:\desarrollo\KeePassCredential

New-Item -ItemType Junction `
    -Path   "$HOME\Documents\PowerShell\Modules\KeePassCredential" `
    -Target 'D:\desarrollo\KeePassCredential'
```

**Or let chezmoi manage the clone** — add to `.chezmoiexternal.toml`:

```toml
["Documents/PowerShell/Modules/KeePassCredential"]
    type = "git-repo"
    url = "https://github.com/<you>/KeePassCredential.git"
    refreshPeriod = "168h"
```

### No profile line needed

Do **not** add `Import-Module` to your profile. The manifest declares every exported function, so PowerShell autoloads the module on first use of one of its commands. A shell that never touches KeePass pays nothing; the ~11 ms load happens on your first `Kp` command.

That only holds if the profile doesn't call `Set-KpVault` either — which is why vaults are declared in a config file the module reads lazily (below), not registered from your profile.

## Setup

### Option A — declare vaults in the config file (recommended)

Create `$XDG_CONFIG_HOME/keepass-credential/vaults.json` (falls back to `~/.config/keepass-credential/vaults.json`; override with `$env:KEEPASSCREDENTIAL_CONFIG`):

```json
[
  { "name": "personal", "path": "D:\\me\\personal.kdbx", "default": true },
  { "name": "shared",   "path": "S:\\team\\shared.kdbx",
    "masterFromVault": "personal", "masterFromEntry": "Shared team vault" }
]
```

Read on first use, not at import. Order does not matter — vaults that unlock on their own are registered before vaults that depend on them. A vault whose path is missing (network drive not mapped) warns once and is skipped rather than breaking the session.

| Key | |
|---|---|
| `name` | Vault name used by `-Vault` |
| `path` | Path to the `.kdbx` |
| `default` | Use this when `-Vault` is omitted |
| `keyFile` | Path to a `.key` / `.keyx` |
| `useUserAccount` | Include the Windows user account key |
| `masterFromVault` | Vault holding this one's master password |
| `masterFromEntry` | Entry in it whose Password field is that key |
| `masterFromGroupPath` | Group of that entry, if the title is ambiguous |

### Option B — register by hand

```powershell
Set-KpVault -Name personal -Path 'D:\me\personal.kdbx' -Default
Set-KpVault -Name shared   -Path 'S:\team\shared.kdbx' `
            -MasterFromVault personal -MasterFromEntry 'Shared team vault'
```

## Generating the config with chezmoi

Real vault paths are machine-specific and shouldn't sit in a public dotfiles repo. Split it the way chezmoi splits any machine-local value: an empty default in the repo, the real values in the machine-local config, and a template that joins them.

**1. Declare the key in `.chezmoidata.yaml`** (public repo):

```yaml
# Empty by design: real vault paths are machine-local and must NOT live in this
# public repo. Add them in ~/.config/chezmoi/chezmoi.toml, one block each:
#
#   [[data.keepassVaults]]
#       name = "personal"
#       path = 'D:\me\personal.kdbx'
#       default = true
#
# Consumed by dot_config/keepass-credential/vaults.json.tmpl.
keepassVaults: []
```

**2. Add the real vaults to `~/.config/chezmoi/chezmoi.toml`** (machine-local, never committed). Plain `[tables]` must stay above `[[array]]` blocks:

```toml
[[data.keepassVaults]]
    name = "personal"
    path = 'D:\me\personal.kdbx'
    default = true

[[data.keepassVaults]]
    name = "shared"
    path = 'S:\team\shared.kdbx'
    masterFromVault = "personal"
    masterFromEntry = "Shared team vault"
```

**3. Add the template at `dot_config/keepass-credential/vaults.json.tmpl`:**

```
[
{{- range $i, $v := .keepassVaults }}{{ if $i }},{{ end }}
  {
    "name": {{ $v.name | quote }},
    "path": {{ $v.path | quote }}
    {{- with dig "default" false $v }},
    "default": true{{ end }}
    {{- with dig "keyFile" "" $v }},
    "keyFile": {{ . | quote }}{{ end }}
    {{- with dig "useUserAccount" false $v }},
    "useUserAccount": true{{ end }}
    {{- with dig "masterFromVault" "" $v }},
    "masterFromVault": {{ . | quote }}{{ end }}
    {{- with dig "masterFromEntry" "" $v }},
    "masterFromEntry": {{ . | quote }}{{ end }}
    {{- with dig "masterFromGroupPath" "" $v }},
    "masterFromGroupPath": {{ . | quote }}{{ end }}
  }
{{- end }}
]
```

> Every optional field goes through `dig` because chezmoi renders with `missingkey=error` — a bare `{{ $v.keyFile }}` aborts the whole template when that key is absent.

**4. Check and apply:**

```powershell
chezmoi execute-template < ~/.local/share/chezmoi/dot_config/keepass-credential/vaults.json.tmpl
chezmoi diff  ~/.config/keepass-credential
chezmoi apply ~/.config/keepass-credential     # the directory, not the file:
                                           # the parent dir is its own target
```

Then, from any new shell:

```powershell
Get-KpVault
```

## Use

```powershell
Enter-PSSession -ComputerName SRV-APP01 -Credential (Get-KpCredential SRV-APP01)
Invoke-Command  -ComputerName SRV-APP01 -Credential (Get-KpCredential SRV-APP01) { hostname }
New-PSSession   -ComputerName SRV01, SRV02 -Credential (Get-KpCredential -Vault shared 'Domain Admin')
```

`Get-KpCredential` returns an ordinary `PSCredential` — the same type `Get-Credential` produces — so it works with `Copy-Item -ToSession`, `Restart-Computer`, `Get-CimInstance`, anything. There are deliberately no wrappers around `Enter-PSSession` / `New-PSSession`: they would only re-declare a subset of those cmdlets' parameters and drift from them.

The master password is asked once per shell session and cached (DPAPI-encrypted) from there on.

### Chained vaults

You unlock `personal` once; `shared` opens transparently behind it. The chained key travels as a `SecureString` and is never written to disk. Circular chains are detected rather than hung on, and a stale key drops the cached copy so fixing the entry and retrying works without restarting the shell.

### Clipboard

```powershell
Copy-KpPassword 'SRV-APP01' -Vault shared     # clears after 12s, as KeePass does
Copy-KpPassword 'SRV-APP01' -Seconds 30
Copy-KpPassword 'SRV-APP01' -Seconds 0        # no auto-clear
Copy-KpUserName 'svc-backup'
```

The clipboard is only cleared if it still holds that password — anything you copy in the meantime survives. The waiting thread keeps a SHA-256 of the value, not a second copy of it.

## Commands

| Command | |
|---|---|
| `Set-KpVault` | Register a vault and how it unlocks |
| `Get-KpVault` | List registered vaults and their state |
| `Get-KpCredential` | Entry → `PSCredential` |
| `Get-KpEntryList` | Titles, users, groups, URLs — no passwords |
| `Copy-KpPassword` | Password → clipboard, with auto-clear |
| `Copy-KpUserName` | User name → clipboard |
| `Clear-KpCache` | Forget cached master keys and credentials |

`Get-KpCredential` takes `-GroupPath` to disambiguate duplicate titles and `-UserName` to override the entry's user name — needed for `DOMAIN\user` forms, and for entries that store only a password.

## Notes

- **Title matching** is exact first, then retried with Unicode whitespace collapsed, so a title stored as `'SRV-APP01 '` or containing a non-breaking space still resolves. If both passes hit, you get an ambiguity error naming the real titles and groups rather than a silent pick — `-eq` is case-insensitive in PowerShell, so `API TOKEN` and `Api Token` would otherwise collide invisibly.
- **Failed lookups name real titles** from the vault, so a stray space or case difference is visible instead of guessed at.
- **Recycle Bin entries** are still enumerable and can match a lookup.
- **Non-domain targets** reached by IP authenticate with NTLM, which gives no delegation — a second hop needs CredSSP or resource-based Kerberos delegation.
- `KeePassCred.ps1` is dot-sourceable on its own under Windows PowerShell 5.1 if you want the KeePassLib layer without the bridge; see `examples/Example_Remoting.ps1`.
