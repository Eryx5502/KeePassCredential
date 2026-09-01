@{
	RootModule        = 'KeePassCredential.psm1'
	ModuleVersion     = '0.1.0'
	GUID              = '6f43b60e-dadc-47e3-ba72-7851a8c39efc'
	Author            = 'abalmaseda'
	Description       = 'KeePass-backed PSCredential objects for PowerShell 7, for remoting and anything else taking -Credential. Bridges to Windows PowerShell 5.1 because KeePassLib is a .NET Framework assembly.'
	PowerShellVersion = '7.0'

	# Windows only: depends on KeePass.exe, Windows PowerShell 5.1 and DPAPI.
	CompatiblePSEditions = @('Core')

	# Listed explicitly so PowerShell can autoload the module on first use of any
	# of these commands - no Import-Module needed in a profile.
	FunctionsToExport = @(
		'Set-KpVault'
		'Get-KpVault'
		'Clear-KpCache'
		'Get-KpCredential'
		'Get-KpEntryList'
		'Copy-KpPassword'
		'Copy-KpUserName'
	)
	CmdletsToExport   = @()
	VariablesToExport = @()
	AliasesToExport   = @()

	PrivateData = @{
		PSData = @{
			Tags       = @('KeePass', 'Credential', 'Remoting', 'PSRemoting', 'Windows')
			ProjectUri = 'https://github.com/abalmaseda/KeePassCredential'
		}
	}
}
