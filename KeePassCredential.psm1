<#
.SYNOPSIS
	KeePass-backed credentials for PowerShell Remoting, usable from PowerShell 7.

.DESCRIPTION
	KeePassLib only loads in Windows PowerShell 5.1, but your interactive shell is
	pwsh 7. This module bridges the two: it shells out to 5.1 to read the entry, and
	the password comes back as a DPAPI blob (CurrentUser scope) that only this
	Windows account can decrypt. No plaintext is ever written to disk, a command
	line, or an environment variable.

	Get-KpCredential returns an ordinary [PSCredential] - the same type Get-Credential
	produces - so it drops straight into any native cmdlet that takes -Credential.
	There are deliberately no wrappers around Enter-PSSession / New-PSSession: they
	would only re-declare a subset of those cmdlets' parameters and drift from them.

	Several vaults can be registered at once, and one vault's master password may be
	stored as an entry in another (-MasterFromVault / -MasterFromEntry). The chained
	key moves as a SecureString and is never written to disk.

.EXAMPLE
	Set-KpVault -Name Personal -Path 'D:\me\Personal.kdbx' -Default
	Set-KpVault -Name Shared   -Path 'S:\team\Shared.kdbx' `
	            -MasterFromVault Personal -MasterFromEntry 'Shared team vault'

	Enter-PSSession -ComputerName SRV-APP01 -Credential (Get-KpCredential -Vault Shared SRV-APP01)
#>

$script:Vaults       = @{}
$script:DefaultVault = $null
$script:CredCache    = @{}
$script:ConfigLoaded = $false
$script:ClearJob     = $null

$script:Ps51   = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$script:Bridge = Join-Path $PSScriptRoot '_KpBridge.ps1'

function Set-KpVault {
	<#
	.SYNOPSIS
		Registers a .kdbx and how it is unlocked. Call once per vault, per session.
	.PARAMETER Name
		Vault name used by -Vault elsewhere. Defaults to 'Default'.
	.PARAMETER Default
		Make this the vault used when -Vault is omitted. The first vault registered
		becomes the default automatically.
	.PARAMETER MasterFromVault
		Name of another registered vault holding this vault's master password.
	.PARAMETER MasterFromEntry
		Title of the entry in -MasterFromVault whose Password field is this vault's
		master password. Read on first use and cached for the session.
	.PARAMETER Prompt
		Ask for the master password now instead of on first use.
	.EXAMPLE
		Set-KpVault -Name Personal -Path 'D:\me\Personal.kdbx'
		Set-KpVault -Name Shared -Path 'S:\team\Shared.kdbx' `
		            -MasterFromVault Personal -MasterFromEntry 'Shared team vault'
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)][string]$Path,
		[string]$Name = 'Default',
		[string]$KeyFile,
		[switch]$UseUserAccount,
		[string]$MasterFromVault,
		[string]$MasterFromEntry,
		[string]$MasterFromGroupPath,
		[switch]$Prompt,
		[switch]$Default
	)

	if(-not (Test-Path -LiteralPath $Path)) { throw "Vault not found: $Path" }
	if($KeyFile -and -not (Test-Path -LiteralPath $KeyFile)) { throw "Key file not found: $KeyFile" }

	if($MasterFromVault -and -not $MasterFromEntry) { throw '-MasterFromVault requires -MasterFromEntry.' }
	if($MasterFromEntry -and -not $MasterFromVault) { throw '-MasterFromEntry requires -MasterFromVault.' }
	if($MasterFromVault) {
		if(-not $script:Vaults.ContainsKey($MasterFromVault)) {
			throw "Vault '$MasterFromVault' is not registered. Register it before the vault that depends on it."
		}
		if($MasterFromVault -eq $Name) { throw "Vault '$Name' cannot hold its own master password." }
		if($Prompt) { throw 'Use either -Prompt or -MasterFromVault, not both.' }
	}

	$script:Vaults[$Name] = @{
		Name                = $Name
		Path                = (Resolve-Path -LiteralPath $Path).ProviderPath
		KeyFile             = if($KeyFile) { (Resolve-Path -LiteralPath $KeyFile).ProviderPath } else { $null }
		UseUserAccount      = [bool]$UseUserAccount
		MasterFromVault     = $MasterFromVault
		MasterFromEntry     = $MasterFromEntry
		MasterFromGroupPath = $MasterFromGroupPath
		MasterBlob          = $null
	}

	# Drop cached credentials for this vault; its definition just changed.
	foreach($k in @($script:CredCache.Keys | Where-Object { $_ -like "$Name`|*" })) { $script:CredCache.Remove($k) }

	if($Default -or -not $script:DefaultVault) { $script:DefaultVault = $Name }

	if($Prompt) {
		$script:Vaults[$Name].MasterBlob = Read-Host -Prompt "Master password for $Name ($(Split-Path $Path -Leaf))" -AsSecureString |
			ConvertFrom-SecureString
	}
}

function Get-KpVault {
	<#
	.SYNOPSIS
		Lists the registered vaults, how each unlocks, and whether it is unlocked yet.
	#>
	[CmdletBinding()]
	param()

	Import-KpVaultConfig

	foreach($n in $script:Vaults.Keys | Sort-Object) {
		$v = $script:Vaults[$n]
		$how = if($v.MasterFromVault) { "entry '$($v.MasterFromEntry)' in $($v.MasterFromVault)" }
		       elseif($v.KeyFile -and $v.UseUserAccount) { 'key file + user account' }
		       elseif($v.KeyFile) { 'key file' }
		       elseif($v.UseUserAccount) { 'user account' }
		       else { 'master password (prompt)' }

		[pscustomobject]@{
			Name     = $n
			Default  = ($n -eq $script:DefaultVault)
			Unlocked = [bool]$v.MasterBlob
			UnlockBy = $how
			Path     = $v.Path
		}
	}
}

function Clear-KpCache {
	<#
	.SYNOPSIS
		Forgets cached master keys and credentials. All vaults unless -Vault is given.
	#>
	[CmdletBinding()]
	param([string]$Vault)

	if($Vault) {
		if(-not $script:Vaults.ContainsKey($Vault)) { throw "No such vault: $Vault" }
		$script:Vaults[$Vault].MasterBlob = $null
		foreach($k in @($script:CredCache.Keys | Where-Object { $_ -like "$Vault`|*" })) { $script:CredCache.Remove($k) }
	}
	else {
		foreach($n in $script:Vaults.Keys) { $script:Vaults[$n].MasterBlob = $null }
		$script:CredCache = @{}
	}
}

function Get-KpConfigPath {
	<#
		Where the vault list lives. Honours XDG_CONFIG_HOME (set in this user's
		profile) and falls back to ~/.config, matching the rest of their dotfiles.
		Override with $env:KEEPASSCREDENTIAL_CONFIG.
	#>
	if($env:KEEPASSCREDENTIAL_CONFIG) { return $env:KEEPASSCREDENTIAL_CONFIG }
	$base = if($env:XDG_CONFIG_HOME) { $env:XDG_CONFIG_HOME } else { Join-Path $HOME '.config' }
	return Join-Path (Join-Path $base 'keepass-credential') 'vaults.json'
}

function Import-KpVaultConfig {
	<#
		Registers the vaults declared in the config file. Called on first use, so a
		shell that never touches KeePass pays nothing: with the manifest in place
		PowerShell autoloads this module only when one of its commands is invoked.

		The file is a JSON array; chezmoi generates it from .keepassVaults.
		Vaults whose key lives in another vault are registered last, so the parent
		always exists regardless of the order in the file.
	#>
	param([switch]$Force)

	if($script:ConfigLoaded -and -not $Force) { return }
	$script:ConfigLoaded = $true

	$path = Get-KpConfigPath
	if(-not (Test-Path -LiteralPath $path)) { return }

	try { $items = @(Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json) }
	catch { Write-Warning "KeePassCredential: $path is not valid JSON - $($_.Exception.Message)"; return }

	# Parents (a vault that unlocks on its own) before children (a vault whose
	# master password sits in another vault).
	foreach($pass in 1, 2) {
		foreach($v in $items) {
			if(-not $v.name -or -not $v.path) { continue }
			$chained = [bool]$v.masterFromVault
			if(($pass -eq 1) -eq $chained) { continue }

			if(-not (Test-Path -LiteralPath $v.path)) {
				Write-Warning "KeePassCredential: vault '$($v.name)' skipped, not found: $($v.path)"
				continue
			}

			$p = @{ Name = $v.name; Path = $v.path }
			if($v.keyFile)             { $p.KeyFile             = $v.keyFile }
			if($v.useUserAccount)      { $p.UseUserAccount      = $true }
			if($v.masterFromVault)     { $p.MasterFromVault     = $v.masterFromVault }
			if($v.masterFromEntry)     { $p.MasterFromEntry     = $v.masterFromEntry }
			if($v.masterFromGroupPath) { $p.MasterFromGroupPath = $v.masterFromGroupPath }
			if($v.default)             { $p.Default             = $true }

			try { Set-KpVault @p }
			catch { Write-Warning "KeePassCredential: vault '$($v.name)' skipped - $($_.Exception.Message)" }
		}
	}
}

function Resolve-KpVaultName {
	param([string]$Vault)

	Import-KpVaultConfig

	if($Vault) {
		if(-not $script:Vaults.ContainsKey($Vault)) {
			throw "No such vault: '$Vault'. Registered: $(($script:Vaults.Keys | Sort-Object) -join ', ')"
		}
		return $Vault
	}
	if(-not $script:DefaultVault) {
		throw "No vault configured. Run Set-KpVault, or declare vaults in $(Get-KpConfigPath)."
	}
	return $script:DefaultVault
}

function Resolve-KpMasterBlob {
	<#
		Returns the DPAPI blob of a vault's master password, or $null when the vault
		opens on a key file / user account alone. $Chain guards against a cycle of
		vaults holding each other's keys.
	#>
	param([string]$Name, [string[]]$Chain = @())

	$v = $script:Vaults[$Name]
	if($v.MasterBlob) { return $v.MasterBlob }

	if($Name -in $Chain) {
		throw "Circular vault dependency: $(($Chain + $Name) -join ' -> ')."
	}

	if($v.MasterFromVault) {
		# The parent vault's entry password IS this vault's master password.
		# Only the Password field is read - never a PSCredential, because an entry
		# that exists purely to hold another vault's key normally has no user name.
		$req = @{ Action = 'Password'; Title = $v.MasterFromEntry }
		if($v.MasterFromGroupPath) { $req.GroupPath = $v.MasterFromGroupPath }

		$res = Invoke-KpBridge -Request $req -Vault $v.MasterFromVault -Chain ($Chain + $Name)
		$v.MasterBlob = $res.Blob
		return $v.MasterBlob
	}

	if(-not $v.KeyFile -and -not $v.UseUserAccount) {
		$v.MasterBlob = Read-Host -Prompt "Master password for $Name ($(Split-Path $v.Path -Leaf))" -AsSecureString |
			ConvertFrom-SecureString
		return $v.MasterBlob
	}

	return $null
}

function Invoke-KpBridge {
	param([hashtable]$Request, [string]$Vault, [string[]]$Chain = @())

	if(-not (Test-Path -LiteralPath $script:Ps51)) { throw "Windows PowerShell 5.1 not found at $script:Ps51" }

	$v = $script:Vaults[$Vault]

	$Request.VaultPath      = $v.Path
	$Request.KeyFile        = $v.KeyFile
	$Request.UseUserAccount = $v.UseUserAccount
	$Request.MasterBlob     = Resolve-KpMasterBlob -Name $Vault -Chain $Chain

	$json = ConvertTo-Json $Request -Compress -Depth 5

	# stdin carries the request, stdout the response.
	$psi = [System.Diagnostics.ProcessStartInfo]::new()
	$psi.FileName = $script:Ps51
	foreach($a in '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $script:Bridge) {
		$psi.ArgumentList.Add($a)
	}
	$psi.RedirectStandardInput  = $true
	$psi.RedirectStandardOutput = $true
	$psi.RedirectStandardError  = $true
	$psi.UseShellExecute        = $false
	# All three streams must be pinned to UTF-8. Left at the default, stdin is
	# written in the console's OEM codepage (CP850 here), which silently degrades
	# any character outside it - a title containing U+20AC arrived as '?' and the
	# entry lookup failed.
	$psi.StandardInputEncoding  = [System.Text.UTF8Encoding]::new($false)
	$psi.StandardOutputEncoding = [System.Text.UTF8Encoding]::new($false)
	$psi.StandardErrorEncoding  = [System.Text.UTF8Encoding]::new($false)

	$p = [System.Diagnostics.Process]::Start($psi)
	$p.StandardInput.Write($json)
	$p.StandardInput.Close()
	$out = $p.StandardOutput.ReadToEnd()
	$err = $p.StandardError.ReadToEnd()
	$p.WaitForExit()

	if([string]::IsNullOrWhiteSpace($out)) {
		throw "KeePass bridge produced no output.$(if($err){ [Environment]::NewLine + $err })"
	}

	$res = $out | ConvertFrom-Json
	if(-not $res.Ok) {
		# A wrong master password is the common case: drop it so the next call
		# re-prompts. For a chained vault, drop the cached copy of the key too -
		# the parent entry may simply be out of date.
		$script:Vaults[$Vault].MasterBlob = $null
		throw "KeePass [$Vault]: $($res.Error)"
	}
	return $res
}

function Get-KpCredentialInternal {
	param([string]$Vault, [string]$Title, [string]$GroupPath, [string]$UserName,
	      [switch]$Refresh, [string[]]$Chain = @())

	$key = "$Vault|$Title|$GroupPath|$UserName"
	if(-not $Refresh -and $script:CredCache.ContainsKey($key)) { return $script:CredCache[$key] }

	$req = @{ Action = 'Get'; Title = $Title }
	if($GroupPath) { $req.GroupPath = $GroupPath }
	if($UserName)  { $req.UserName  = $UserName }

	$res  = Invoke-KpBridge -Request $req -Vault $Vault -Chain $Chain
	$cred = [System.Management.Automation.PSCredential]::new(
		$res.UserName, (ConvertTo-SecureString -String $res.Blob))

	$script:CredCache[$key] = $cred
	return $cred
}

function Get-KpCredential {
	<#
	.SYNOPSIS
		Returns a [PSCredential] for a KeePass entry - the same type Get-Credential
		returns, so it works with any -Credential parameter.
	.PARAMETER Vault
		Which registered vault to read. Defaults to the default vault.
	.PARAMETER Refresh
		Bypass the per-session cache and re-read the entry.
	.EXAMPLE
		Enter-PSSession -ComputerName SRV-APP01 -Credential (Get-KpCredential SRV-APP01)
	.EXAMPLE
		Get-KpCredential -Vault Shared 'SRV-APP01'
	#>
	[CmdletBinding()]
	[OutputType([System.Management.Automation.PSCredential])]
	param(
		[Parameter(Mandatory, Position = 0)][string]$Title,
		[string]$Vault,
		[string]$GroupPath,
		[string]$UserName,
		[switch]$Refresh
	)

	Get-KpCredentialInternal -Vault (Resolve-KpVaultName $Vault) -Title $Title `
		-GroupPath $GroupPath -UserName $UserName -Refresh:$Refresh
}

function Get-KpEntryList {
	<#
	.SYNOPSIS
		Lists every entry in a vault (title, user, group, URL). No passwords.
	#>
	[CmdletBinding()]
	param([string]$Vault)

	(Invoke-KpBridge -Request @{ Action = 'List' } -Vault (Resolve-KpVaultName $Vault)).Entries
}

function Copy-KpSecretToClipboard {
	param([string]$Value, [int]$Seconds, [string]$What)

	Set-Clipboard -Value $Value

	if($Seconds -le 0) {
		Write-Verbose "$What copied; auto-clear disabled."
		return
	}

	# Clear only if the clipboard still holds what we put there, so a later copy
	# by the user is never clobbered. Compared by hash so the waiting thread does
	# not keep a second plaintext copy of the secret.
	$sha = [System.Security.Cryptography.SHA256]::Create()
	try { $hash = [Convert]::ToBase64String($sha.ComputeHash([System.Text.Encoding]::Unicode.GetBytes($Value))) }
	finally { $sha.Dispose() }

	# One pending clear at a time.
	if($script:ClearJob) { Remove-Job -Job $script:ClearJob -Force -ErrorAction Ignore }
	$script:ClearJob = Start-ThreadJob -ArgumentList $Seconds, $hash -ScriptBlock {
		param($Seconds, $Hash)
		Start-Sleep -Seconds $Seconds
		$cur = Get-Clipboard -Raw
		if([string]::IsNullOrEmpty($cur)) { return }
		$sha = [System.Security.Cryptography.SHA256]::Create()
		try { $now = [Convert]::ToBase64String($sha.ComputeHash([System.Text.Encoding]::Unicode.GetBytes($cur))) }
		finally { $sha.Dispose() }
		if($now -eq $Hash) { Set-Clipboard -Value '' }
	}
}

function Copy-KpPassword {
	<#
	.SYNOPSIS
		Copies an entry's password to the clipboard, clearing it after a delay.
	.PARAMETER Seconds
		Seconds before the clipboard is cleared. Default 12, as in KeePass itself.
		0 disables clearing. The clipboard is only cleared if it still holds this
		password, so anything you copy in the meantime survives.
	.EXAMPLE
		Copy-KpPassword 'SRV-APP01' -Vault shared
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory, Position = 0)][string]$Title,
		[string]$Vault,
		[string]$GroupPath,
		[int]$Seconds = 12
	)

	$v   = Resolve-KpVaultName $Vault
	$req = @{ Action = 'Password'; Title = $Title }
	if($GroupPath) { $req.GroupPath = $GroupPath }

	$res = Invoke-KpBridge -Request $req -Vault $v
	$ss  = ConvertTo-SecureString -String $res.Blob
	$net = [System.Net.NetworkCredential]::new('', $ss)
	try { Copy-KpSecretToClipboard -Value $net.Password -Seconds $Seconds -What 'Password' }
	finally { $net.Password = $null }

	Write-Host "Password for '$Title' copied$(if($Seconds -gt 0){" - clipboard clears in ${Seconds}s"})." -ForegroundColor DarkGray
}

function Copy-KpUserName {
	<#
	.SYNOPSIS
		Copies an entry's user name to the clipboard.
	.PARAMETER Seconds
		Seconds before clearing. Default 0 - a user name is not a secret.
	.EXAMPLE
		Copy-KpUserName 'svc-backup' -Vault shared
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory, Position = 0)][string]$Title,
		[string]$Vault,
		[string]$GroupPath,
		[int]$Seconds = 0
	)

	# Read the UserName field directly rather than going through a PSCredential:
	# many entries in a shared vault have no user name, and that must report
	# cleanly instead of tripping the credential guard.
	$v   = Resolve-KpVaultName $Vault
	$req = @{ Action = 'Field'; Title = $Title; Field = 'UserName' }
	if($GroupPath) { $req.GroupPath = $GroupPath }

	$user = (Invoke-KpBridge -Request $req -Vault $v).Value

	if([string]::IsNullOrEmpty($user)) {
		Write-Warning "Entry '$Title' has no user name."
		return
	}

	Copy-KpSecretToClipboard -Value $user -Seconds $Seconds -What 'User name'
	Write-Host "User name for '$Title' copied: $user" -ForegroundColor DarkGray
}

Export-ModuleMember -Function Set-KpVault, Get-KpVault, Clear-KpCache, Get-KpCredential, Get-KpEntryList,
	Copy-KpPassword, Copy-KpUserName
