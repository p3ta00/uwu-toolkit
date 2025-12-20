<#
.SYNOPSIS
    UwU Quick Enum - One-shot AD enumeration for remote execution

.DESCRIPTION
    Compact enumeration script designed for remote execution via WMI/WinRM.
    Outputs key findings to console. Load PowerView first!

.EXAMPLE
    # Remote via netexec:
    nxc smb TARGET -u USER -p PASS -X '. C:\Tools\PowerView.ps1; IEX(Get-Content C:\Tools\UwU-QuickEnum.ps1 -Raw)'
#>

Write-Host "`n[*] UwU Quick AD Enum" -ForegroundColor Magenta
Write-Host "=" * 40

# Domain Info
Write-Host "`n[+] DOMAIN:" -ForegroundColor Cyan
$d = Get-Domain
Write-Host "    Name: $($d.Name)"
Write-Host "    Forest: $($d.Forest)"

# Domain Controllers
Write-Host "`n[+] DOMAIN CONTROLLERS:" -ForegroundColor Cyan
Get-DomainController | ForEach-Object { Write-Host "    $($_.Name) - $($_.IPAddress)" }

# Trusts
Write-Host "`n[+] DOMAIN TRUSTS:" -ForegroundColor Cyan
Get-DomainTrust | ForEach-Object { Write-Host "    $($_.TargetName) [$($_.TrustDirection)]" }

# User Count
$uc = (Get-DomainUser | Measure-Object).Count
Write-Host "`n[+] TOTAL USERS: $uc" -ForegroundColor Cyan

# Computer Count
$cc = (Get-DomainComputer | Measure-Object).Count
Write-Host "[+] TOTAL COMPUTERS: $cc" -ForegroundColor Cyan

# Kerberoastable
Write-Host "`n[+] KERBEROASTABLE USERS (SPN):" -ForegroundColor Yellow
Get-DomainUser -SPN | ForEach-Object { Write-Host "    $($_.samaccountname)" -ForegroundColor White }

# AS-REP Roastable
Write-Host "`n[+] AS-REP ROASTABLE (No Preauth):" -ForegroundColor Yellow
Get-DomainUser -PreauthNotRequired | ForEach-Object { Write-Host "    $($_.samaccountname)" -ForegroundColor White }

# Constrained Delegation
Write-Host "`n[+] CONSTRAINED DELEGATION:" -ForegroundColor Yellow
Get-DomainUser -TrustedToAuth | ForEach-Object { Write-Host "    $($_.samaccountname)" -ForegroundColor White }

# Users with Descriptions
Write-Host "`n[+] USERS WITH DESCRIPTIONS (check for passwords!):" -ForegroundColor Red
Get-DomainUser -Properties samaccountname,description | Where-Object { $_.description } | ForEach-Object {
    Write-Host "    $($_.samaccountname): $($_.description)" -ForegroundColor White
}

# Domain Admins
Write-Host "`n[+] DOMAIN ADMINS:" -ForegroundColor Cyan
Get-DomainGroupMember -Identity "Domain Admins" | ForEach-Object { Write-Host "    $($_.MemberName)" }

# Foreign Group Members
Write-Host "`n[+] FOREIGN GROUP MEMBERS (Cross-Domain):" -ForegroundColor Yellow
Get-DomainForeignGroupMember | ForEach-Object {
    Write-Host "    $($_.MemberName) in $($_.GroupName)" -ForegroundColor White
}

# GPOs
Write-Host "`n[+] GROUP POLICY OBJECTS:" -ForegroundColor Cyan
Get-DomainGPO -Properties displayname,name | ForEach-Object {
    Write-Host "    $($_.displayname): $($_.name)"
}

Write-Host "`n[*] Quick enum complete!" -ForegroundColor Green
Write-Host "    Run Invoke-UwUEnum for full enumeration`n" -ForegroundColor Magenta
