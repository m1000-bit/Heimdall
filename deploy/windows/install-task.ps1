<#
.SYNOPSIS
    Installs the Heimdall Sentinel daemon as a scheduled task.

.DESCRIPTION
    Copies the release binary, creates the data directory, registers the
    scheduled task from the XML next to this script, and grants the account
    the "log on as a batch job" right it needs.

    Run it from an elevated PowerShell prompt:
        powershell -ExecutionPolicy Bypass -File deploy\windows\install-task.ps1

.PARAMETER Account
    The local account the daemon runs as. It should be an account used for
    nothing else: a scheduled task is not a sandbox, so the daemon gets
    exactly the rights of this account and no more.

.PARAMETER InstallDir
    Where the daemon is installed. Defaults to 'C:\Program Files\Heimdall'.

.PARAMETER DataDir
    Where the keystore, the published identity and the learned baselines
    live. Defaults to 'C:\ProgramData\Heimdall'.
#>

[CmdletBinding()]
param(
    [string] $Account = 'heimdall',
    [string] $InstallDir = 'C:\Program Files\Heimdall',
    [string] $DataDir = 'C:\ProgramData\Heimdall',
    [string] $TaskName = 'Heimdall Sentinel'
)

$ErrorActionPreference = 'Stop'

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-SourceBinary {
    $repo = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $binary = Join-Path $repo 'target\release\heimdall-sentinel.exe'
    if (-not (Test-Path -LiteralPath $binary)) {
        throw "no release build found at $binary -- run: cargo build --release -p heimdall-sentinel"
    }
    return $binary
}

if (-not (Test-Administrator)) {
    throw 'this installer needs an elevated prompt'
}

if (-not (Get-LocalUser -Name $Account -ErrorAction SilentlyContinue)) {
    throw "the local account $Account does not exist -- create it first: New-LocalUser -Name $Account -NoPassword -UserMayNotChangePassword"
}

$binary = Get-SourceBinary
$here = Split-Path -Parent $PSCommandPath

Write-Host "installing the daemon into $InstallDir"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item -LiteralPath $binary -Destination (Join-Path $InstallDir 'heimdall-sentinel.exe') -Force

Write-Host "preparing $DataDir"
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $DataDir 'baselines') | Out-Null

# The account owns its own data and nothing else.
$account = Get-LocalUser -Name $Account
$acl = Get-Acl -LiteralPath $DataDir
$acl.SetAccessRuleProtection($true, $false)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    $Account, 'Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
$acl.SetAccessRule($rule)
Set-Acl -LiteralPath $DataDir -AclObject $acl

# "Log on as a batch job", which is what S4U needs.
Write-Host "granting the batch job right to $Account"
$secedit = "$env:windir\System32\secedit.exe"
& $secedit /export /cfg "$env:TEMP\heimdall-secedit.cfg" /quiet | Out-Null
try {
    $content = Get-Content -LiteralPath "$env:TEMP\heimdall-secedit.cfg" -Raw
    $content = $content -replace '(?m)^(SeBatchLogonRight\s*=\s*).*$', "`$1$Account"
    Set-Content -LiteralPath "$env:TEMP\heimdall-secedit.cfg" -Value $content -Encoding Unicode
    & $secedit /configure /cfg "$env:TEMP\heimdall-secedit.cfg" /quiet | Out-Null
} finally {
    Remove-Item -LiteralPath "$env:TEMP\heimdall-secedit.cfg" -ErrorAction SilentlyContinue
}

Write-Host "registering the scheduled task"
$xmlPath = Join-Path $here 'heimdall-sentinel-task.xml'
$xml = Get-Content -LiteralPath $xmlPath -Raw
$xml = $xml.Replace('HEIMDALL_USER', $Account)
$xml = $xml.Replace('C:\Program Files\Heimdall\heimdall-sentinel.exe', (Join-Path $InstallDir 'heimdall-sentinel.exe'))
$xml = $xml.Replace('C:\ProgramData\Heimdall', $DataDir)
$tempXml = Join-Path $env:TEMP 'heimdall-sentinel-task.xml'
Set-Content -LiteralPath $tempXml -Value $xml -Encoding UTF8

Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName $TaskName -Xml (Get-Content -LiteralPath $tempXml -Raw) -TaskPath '\Heimdall\' | Out-Null
Remove-Item -LiteralPath $tempXml -ErrorAction SilentlyContinue

Write-Host ''
Write-Host 'The task is registered but not started.'
Write-Host ''
Write-Host 'Before the first start:'
Write-Host '  1. Start it:        Start-ScheduledTask -TaskName "' + $TaskName + '"'
Write-Host '  2. Read its identity from the task log, and from'
Write-Host '     ' + (Join-Path $DataDir 'published\sentinel.identity')
Write-Host '  3. Pin it in Core with HEIMDALL_SENTINEL_ID, and point Core at the'
Write-Host '     pipe with HEIMDALL_ENDPOINT=heimdall-sentinel'
Write-Host ''
Write-Host 'The named pipe uses the default Windows security descriptor, so Core'
Write-Host 'has to run as the same account as the daemon. Running the daemon'
Write-Host 'under the operator''s own account is the simplest arrangement.'
