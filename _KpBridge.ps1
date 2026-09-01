<#
	Internal worker. Runs under Windows PowerShell 5.1 ONLY.

	Reads a JSON request on stdin, opens the KeePass database, and writes a JSON
	response on stdout in which the password is a DPAPI blob (ConvertFrom-SecureString,
	CurrentUser scope). Plaintext never crosses the process boundary.

	Not meant to be called directly - KeePassCredential.psm1 drives it.
#>

# Windows PowerShell 5.1 launched as a child of pwsh 7 inherits pwsh's
# PSModulePath, so 'Microsoft.PowerShell.Security' resolves to the 7.x copy and
# fails to import ("Ya existe el miembro AuditToString" / type-data collision).
# Restore the 5.1 search path before anything else touches a module.
$env:PSModulePath = @(
	"$HOME\Documents\WindowsPowerShell\Modules",
	"$env:ProgramFiles\WindowsPowerShell\Modules",
	"$env:SystemRoot\System32\WindowsPowerShell\v1.0\Modules"
) -join ';'

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

function Write-Response($obj) {
	[Console]::Out.Write((ConvertTo-Json $obj -Compress -Depth 5))
}

try {
	# Read stdin as UTF-8 explicitly. [Console]::In decodes with the process's
	# input codepage, which loses characters outside it (see KeePassCredential.psm1).
	$stdin = New-Object System.IO.StreamReader @([Console]::OpenStandardInput(), (New-Object System.Text.UTF8Encoding @($false)))
	$req = $stdin.ReadToEnd() | ConvertFrom-Json

	. (Join-Path $PSScriptRoot 'KeePassCred.ps1')

	$open = @{ Path = $req.VaultPath }
	if($req.MasterBlob)     { $open.MasterPassword = ConvertTo-SecureString -String $req.MasterBlob }
	if($req.KeyFile)        { $open.KeyFile        = $req.KeyFile }
	if($req.UseUserAccount) { $open.UseUserAccount = $true }

	$pd = Open-KeePassDatabase @open
	try {
		if($req.Action -eq 'List') {
			$items = foreach($pe in $pd.RootGroup.GetEntries($true)) {
				[pscustomobject]@{
					Title = $pe.Strings.ReadSafe([KeePassLib.PwDefs]::TitleField)
					User  = $pe.Strings.ReadSafe([KeePassLib.PwDefs]::UserNameField)
					Group = $pe.ParentGroup.GetFullPath('/', $false)
					Url   = $pe.Strings.ReadSafe([KeePassLib.PwDefs]::UrlField)
				}
			}
			Write-Response @{ Ok = $true; Entries = @($items) }
		}
		elseif($req.Action -eq 'Password') {
			# Just the Password field, as a DPAPI blob. Used to unlock a vault whose
			# master password lives in another vault: such an entry usually has no
			# user name, so it must not be forced through a PSCredential.
			$f = @{ Database = $pd; Title = $req.Title; Field = 'Password' }
			if($req.GroupPath) { $f.GroupPath = $req.GroupPath }
			Write-Response @{ Ok = $true; Blob = (Get-KeePassField @f | ConvertFrom-SecureString) }
		}
		elseif($req.Action -eq 'Field') {
			# Non-secret fields only. The password must travel as a DPAPI blob via the
			# 'Password' action, never as plaintext on stdout.
			if($req.Field -eq [KeePassLib.PwDefs]::PasswordField) {
				throw "Use the 'Password' action to read the password field."
			}
			$f = @{ Database = $pd; Title = $req.Title; Field = $req.Field; AsPlainText = $true }
			if($req.GroupPath) { $f.GroupPath = $req.GroupPath }
			Write-Response @{ Ok = $true; Value = (Get-KeePassField @f) }
		}
		else {
			$get = @{ Database = $pd; Title = $req.Title }
			if($req.GroupPath) { $get.GroupPath = $req.GroupPath }
			if($req.UserName)  { $get.UserName  = $req.UserName }

			$cred = Get-KeePassCredential @get
			Write-Response @{
				Ok       = $true
				UserName = $cred.UserName
				Blob     = ($cred.Password | ConvertFrom-SecureString)
			}
		}
	}
	finally { Close-KeePassDatabase $pd }
}
catch {
	Write-Response @{ Ok = $false; Error = $_.Exception.Message }
	exit 1
}
