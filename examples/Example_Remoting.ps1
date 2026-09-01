<#
.SYNOPSIS
	Opens a KeePass database, pulls credentials out of it and uses them for
	PowerShell Remoting (WinRM).

.NOTES
	Run under Windows PowerShell 5.1:
		powershell.exe -ExecutionPolicy Bypass -File .\Example_Remoting.ps1
#>

$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
. (Join-Path $PSScriptRoot '..\KeePassCred.ps1')

# --- 1. Unlock the database -------------------------------------------------
# Pick ONE of these. Prompting is the safest for interactive use; a key file
# plus -UseUserAccount is the usual choice for unattended/scheduled runs,
# because it needs no secret stored in the script.

$masterPwd = Read-Host -Prompt 'KeePass master password' -AsSecureString
$pd = Open-KeePassDatabase -Path '_Database.kdbx' -MasterPassword $masterPwd

# $pd = Open-KeePassDatabase -Path 'D:\vault\Servers.kdbx' `
#         -KeyFile 'D:\vault\Servers.keyx' -UseUserAccount

try {
	# --- 2. One host --------------------------------------------------------
	# Entry title = host name, UserName/Password fields = the remoting account.

	$cred = Get-KeePassCredential -Database $pd -Title 'SRV-APP01' -GroupPath 'Servers'

	Invoke-Command -ComputerName 'SRV-APP01' -Credential $cred -ScriptBlock {
		[pscustomobject]@{
			Host   = $env:COMPUTERNAME
			RanAs  = "$env:USERDOMAIN\$env:USERNAME"
			Uptime = (Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
		}
	}

	# --- 3. Many hosts, each with its own account ---------------------------
	# Reuse sessions instead of re-authenticating per command.

	$hosts = 'SRV-APP01', 'SRV-APP02', 'SRV-SQL01'
	$sessions = foreach($h in $hosts) {
		try {
			New-PSSession -ComputerName $h -Credential (Get-KeePassCredential -Database $pd -Title $h)
		}
		catch { Write-Warning "$h : $($_.Exception.Message)" }
	}

	try {
		Invoke-Command -Session $sessions -ScriptBlock { Get-Service -Name WinRM } |
			Select-Object PSComputerName, Name, Status
	}
	finally {
		if($sessions) { Remove-PSSession -Session $sessions }
	}

	# --- 4. Same account for every host -------------------------------------
	# $admin = Get-KeePassCredential -Database $pd -Title 'Domain Admin' -UserName 'CONTOSO\svc-remote'
	# Invoke-Command -ComputerName $hosts -Credential $admin { hostname }

	# --- 5. Non-domain target over HTTPS ------------------------------------
	# $so = New-PSSessionOption -SkipCACheck:$false
	# Invoke-Command -ComputerName 'srv.example.com' -UseSSL -Port 5986 `
	#     -Credential $cred -SessionOption $so { hostname }
}
finally {
	# --- 6. Always close ----------------------------------------------------
	# Closing drops the decrypted database from memory. The PSCredential
	# objects stay usable; their passwords live in SecureStrings.
	Close-KeePassDatabase $pd
}
