<#
.SYNOPSIS
	Helper functions to read credentials out of a KeePass 2.x (.kdbx) database
	and hand them to PowerShell as [PSCredential] objects, e.g. for PS Remoting.

.NOTES
	REQUIRES Windows PowerShell 5.1. KeePass.exe is a .NET Framework assembly;
	PowerShell 7 (.NET) cannot load it (System.Security.Cryptography.ProtectedMemory
	does not exist there).

	Dot-source this file:  . '.\KeePassCred.ps1'
#>

$script:KpInitialized = $false

function Initialize-KeePassLib {
	[CmdletBinding()]
	param(
		[string]$KeePassPath = 'C:\Program Files\KeePass Password Safe 2\KeePass.exe'
	)

	if($script:KpInitialized) { return }

	if(-not (Test-Path -LiteralPath $KeePassPath)) {
		throw "KeePass.exe not found at '$KeePassPath'."
	}
	if($PSVersionTable.PSEdition -eq 'Core') {
		throw 'KeePassLib requires Windows PowerShell 5.1; run this under powershell.exe, not pwsh.exe.'
	}

	[System.Reflection.Assembly]::LoadFrom($KeePassPath) | Out-Null
	[KeePass.Program]::CommonInitialize() | Out-Null
	$script:KpInitialized = $true
}

function Open-KeePassDatabase {
	<#
	.SYNOPSIS
		Opens a .kdbx and returns the KeePassLib.PwDatabase object.
	.PARAMETER MasterPassword
		Master password as a SecureString.
	.PARAMETER KeyFile
		Path to a .key / .keyx key file.
	.PARAMETER UseUserAccount
		Include the Windows user account key (KcpUserAccount) in the composite key.
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)][string]$Path,
		[securestring]$MasterPassword,
		[string]$KeyFile,
		[switch]$UseUserAccount
	)

	Initialize-KeePassLib

	if(-not $MasterPassword -and -not $KeyFile -and -not $UseUserAccount) {
		throw 'Specify at least one of -MasterPassword, -KeyFile, -UseUserAccount.'
	}

	$ck = New-Object KeePassLib.Keys.CompositeKey

	if($MasterPassword) {
		# Marshal the SecureString to UTF-8 bytes without ever creating a
		# managed System.String holding the master password.
		$bstr  = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($MasterPassword)
		$chars = $null
		$bytes = $null
		try {
			$chars = New-Object char[] $MasterPassword.Length
			for($i = 0; $i -lt $chars.Length; ++$i) {
				$chars[$i] = [char][System.Runtime.InteropServices.Marshal]::ReadInt16($bstr, $i * 2)
			}
			$bytes = [System.Text.Encoding]::UTF8.GetBytes($chars)
			$ck.AddUserKey([KeePassLib.Keys.KcpPassword]::new($bytes))
		}
		finally {
			[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
			if($chars) { for($i = 0; $i -lt $chars.Length; ++$i) { $chars[$i] = [char]0 } }
			if($bytes) { [KeePassLib.Utility.MemUtil]::ZeroByteArray($bytes) }
		}
	}

	if($KeyFile) {
		$kfFull = (Resolve-Path -LiteralPath $KeyFile).ProviderPath
		$ck.AddUserKey([KeePassLib.Keys.KcpKeyFile]::new($kfFull))
	}

	if($UseUserAccount) {
		$ck.AddUserKey((New-Object KeePassLib.Keys.KcpUserAccount))
	}

	$dbFull = (Resolve-Path -LiteralPath $Path).ProviderPath
	$ioc = [KeePassLib.Serialization.IOConnectionInfo]::FromPath($dbFull)

	$pd = New-Object KeePassLib.PwDatabase
	$pd.Open($ioc, $ck, $null)   # throws InvalidCompositeKeyException on a wrong key
	return $pd
}

function Close-KeePassDatabase {
	[CmdletBinding()]
	param([Parameter(Mandatory, ValueFromPipeline)]$Database)
	process { if($Database -and $Database.IsOpen) { $Database.Close() } }
}

function ConvertTo-SecureStringFromProtected {
	# KeePassLib.Security.ProtectedString -> SecureString, via char[] that we wipe.
	param([Parameter(Mandatory)]$ProtectedString)

	$ss = New-Object System.Security.SecureString
	$chars = $ProtectedString.ReadChars()
	try {
		foreach($c in $chars) { $ss.AppendChar($c) }
	}
	finally {
		for($i = 0; $i -lt $chars.Length; ++$i) { $chars[$i] = [char]0 }
	}
	$ss.MakeReadOnly()
	return $ss
}

function ConvertTo-KpComparableTitle {
	# Titles typed by hand in KeePass routinely carry a trailing space or a
	# non-breaking space, which renders identically to a normal one but breaks an
	# exact match. Collapse every Unicode whitespace run (.NET \s covers U+00A0,
	# which is category Zs) to a single space and trim.
	param([string]$Value)
	if([string]::IsNullOrEmpty($Value)) { return '' }
	return ([regex]::Replace($Value, '\s+', ' ')).Trim()
}

function Test-KpGroupPath {
	param($Entry, [string]$GroupPath)
	if(-not $GroupPath) { return $true }
	$full = $Entry.ParentGroup.GetFullPath('/', $false)
	$want = $GroupPath.Trim('/')
	return ($full -eq $want -or $full.EndsWith('/' + $want))
}

function Get-KeePassEntry {
	<#
	.SYNOPSIS
		Finds entries by title (and optionally by group path).
	.DESCRIPTION
		Exact, case-insensitive match first. If that finds nothing, retries with
		whitespace normalised, so a title stored as 'SRV-APP01 ' or with a
		non-breaking space still resolves.
	.PARAMETER GroupPath
		Group path relative to the root, e.g. 'Servers/Production'.
		Matching is done on the trailing part of the full path.
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]$Database,
		[Parameter(Mandatory)][string]$Title,
		[string]$GroupPath
	)

	$exact = @()
	$loose = @()
	$wanted = ConvertTo-KpComparableTitle $Title

	foreach($pe in $Database.RootGroup.GetEntries($true)) {
		if(-not (Test-KpGroupPath $pe $GroupPath)) { continue }

		$t = $pe.Strings.ReadSafe([KeePassLib.PwDefs]::TitleField)
		if($t -eq $Title) { $exact += $pe }
		elseif((ConvertTo-KpComparableTitle $t) -eq $wanted) { $loose += $pe }
	}

	# When both passes hit, return everything so the caller reports an ambiguity
	# rather than silently preferring one. 'API TOKEN' and 'Api Token'
	# are equal to -eq (case-insensitive), so a quiet "exact wins" rule would pick
	# one of two different secrets without saying so.
	if($exact.Count -and $loose.Count) { return @($exact) + @($loose) }
	if($exact.Count) { return $exact }
	return $loose
}

function Get-KpTitleHint {
	# Builds the 'did you mean' tail for a failed lookup: real titles from the
	# vault, quoted, so a stray space or a case difference is visible.
	param($Database, [string]$Title)

	$needle = ConvertTo-KpComparableTitle $Title
	$near = @()
	foreach($pe in $Database.RootGroup.GetEntries($true)) {
		$t = $pe.Strings.ReadSafe([KeePassLib.PwDefs]::TitleField)
		if([string]::IsNullOrEmpty($t)) { continue }
		$c = ConvertTo-KpComparableTitle $t
		if($c.IndexOf($needle, [StringComparison]::OrdinalIgnoreCase) -ge 0 -or
		   $needle.IndexOf($c, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
			$near += "'$t' (in $($pe.ParentGroup.GetFullPath('/', $false)))"
		}
	}
	$near = @($near | Select-Object -Unique | Select-Object -First 8)
	if($near.Count) { return " Similar titles: $($near -join '; ')." }
	return ' Run Get-KpEntryList to see the available titles.'
}

function Get-KeePassCredential {
	<#
	.SYNOPSIS
		Returns a [PSCredential] built from a KeePass entry's UserName + Password.
	.PARAMETER UserName
		Overrides the entry's user name (useful for 'DOMAIN\user' forms).
	.EXAMPLE
		$cred = Get-KeePassCredential -Database $pd -Title 'SRV-APP01'
		Invoke-Command -ComputerName SRV-APP01 -Credential $cred { hostname }
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]$Database,
		[Parameter(Mandatory)][string]$Title,
		[string]$GroupPath,
		[string]$UserName
	)

	$entries = @(Get-KeePassEntry -Database $Database -Title $Title -GroupPath $GroupPath)
	if($entries.Count -eq 0) {
		throw "No KeePass entry with title '$Title'$(if($GroupPath){" in group '$GroupPath'"}).$(Get-KpTitleHint $Database $Title)"
	}
	if($entries.Count -gt 1) {
		$where = ($entries | ForEach-Object {
			"'$($_.Strings.ReadSafe([KeePassLib.PwDefs]::TitleField))' in $($_.ParentGroup.GetFullPath('/', $false))"
		}) -join '; '
		throw "Title '$Title' is ambiguous ($($entries.Count) matches: $where). Use -GroupPath to pick one."
	}

	$pe = $entries[0]
	$user = if($UserName) { $UserName } else { $pe.Strings.ReadSafe([KeePassLib.PwDefs]::UserNameField) }
	if([string]::IsNullOrEmpty($user)) { throw "Entry '$Title' has an empty user name; pass -UserName." }

	$psPwd = $pe.Strings.Get([KeePassLib.PwDefs]::PasswordField)
	if($null -eq $psPwd) { throw "Entry '$Title' has no password." }

	return New-Object System.Management.Automation.PSCredential @($user, (ConvertTo-SecureStringFromProtected $psPwd))
}

function Get-KeePassField {
	<#
	.SYNOPSIS
		Reads any field of an entry (standard or custom string) as a SecureString,
		or as plaintext with -AsPlainText.
	.EXAMPLE
		Get-KeePassField -Database $pd -Title 'SRV-APP01' -Field 'URL' -AsPlainText
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]$Database,
		[Parameter(Mandatory)][string]$Title,
		[Parameter(Mandatory)][string]$Field,
		[string]$GroupPath,
		[switch]$AsPlainText
	)

	$entries = @(Get-KeePassEntry -Database $Database -Title $Title -GroupPath $GroupPath)
	if($entries.Count -eq 0) {
		throw "No KeePass entry with title '$Title'$(if($GroupPath){" in group '$GroupPath'"}).$(Get-KpTitleHint $Database $Title)"
	}
	if($entries.Count -gt 1) {
		$where = ($entries | ForEach-Object {
			"'$($_.Strings.ReadSafe([KeePassLib.PwDefs]::TitleField))' in $($_.ParentGroup.GetFullPath('/', $false))"
		}) -join '; '
		throw "Title '$Title' is ambiguous ($($entries.Count) matches: $where). Use -GroupPath to pick one."
	}

	$ps = $entries[0].Strings.Get($Field)
	if($null -eq $ps) { throw "Entry '$Title' has no field '$Field'. Available: $($entries[0].Strings.GetKeys() -join ', ')" }

	if($AsPlainText) { return $ps.ReadString() }
	return ConvertTo-SecureStringFromProtected $ps
}
