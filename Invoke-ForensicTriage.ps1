














































































































































[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidatePattern('^[A-Za-z0-9._-]*$')]
    [string]$CaseId = '',

    
    
    [Parameter(Mandatory = $false)]
    [string]$FleetRoot = '',

    [Parameter(Mandatory = $false)]
    [string]$Examiner = '(no indicado)',

    [Parameter(Mandatory = $false)]
    [string]$Organization = '(no indicado)',

    [Parameter(Mandatory = $false)]
    
    [datetime]$StartDate = (Get-Date).AddYears(-10),

    [Parameter(Mandatory = $false)]
    [datetime]$EndDate = (Get-Date),

    
    
    
    [Parameter(Mandatory = $false)]
    [datetime]$IncidentStart = [datetime]::MinValue,
    [Parameter(Mandatory = $false)]
    [datetime]$IncidentEnd = [datetime]::MinValue,

    
    
    
    
    [Parameter(Mandatory = $false)]
    [datetime]$ExaminerSince = [datetime]::MinValue,

    
    
    [Parameter(Mandatory = $false)]
    [int]$MaxScanSecondsPerRoot = 180,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = '',

    [Parameter(Mandatory = $false)]
    [string]$TimeZone = '',

    [Parameter(Mandatory = $false)]
    [string]$TargetComputer = $env:COMPUTERNAME,

    [Parameter(Mandatory = $false)]
    [ValidateSet('All','SystemInfo','Users','EventLogs','Registry','FileSystem',
                 'RemoteAccess','Network','Volatile','Persistence','DeletedFiles','UserActivity','ProgramExecution','USBDevices','BrowserActivity','PasswordActivity','LogonCorrelation','HistoricalLogs','EvidencePreservation','SecurityTools','AITools')]
    [string[]]$Modules = @('All'),

    [bool]$IncludeVolatileData          = $true,
    [bool]$IncludeEventLogs             = $true,
    [bool]$IncludeFileSystemArtifacts   = $true,
    [bool]$IncludeRemoteAccessArtifacts = $true,
    [bool]$IncludeNetworkArtifacts      = $true,
    [bool]$IncludeUserArtifacts         = $true,
    [bool]$IncludePersistenceArtifacts  = $true,
    [bool]$IncludeHashes                = $true,

    [ValidateSet('SHA256','SHA512')]
    [string[]]$HashAlgorithms = @('SHA256'),

    [long]$MaximumFileSizeForHashing = 1GB,

    [bool]$ExportRawEvidence    = $true,
    [bool]$ExportParsedEvidence = $true,
    [bool]$CompressOutput       = $false,
    [bool]$ReadOnlyMode         = $true,
    [switch]$VerboseLogging
)




$script:ScriptVersion   = '1.0.0'
$script:AcquisitionId   = ('{0}_{1}_{2}' -f $script:CaseId, $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd_HHmmss'))
$script:StartLocal      = Get-Date
$script:StartUtc        = $script:StartLocal.ToUniversalTime()
$script:CommandLog      = New-Object System.Collections.ArrayList   
$script:ErrorLog        = New-Object System.Collections.ArrayList
$script:WarningLog      = New-Object System.Collections.ArrayList
$script:EvidenceList    = New-Object System.Collections.ArrayList   
$script:SourcesQueried  = New-Object System.Collections.ArrayList
$script:MissingEvidence = New-Object System.Collections.ArrayList   
$script:IsAdmin         = $false   
$script:IsInAdminsGroup = $false   
$script:IntegrityLevel  = 'Desconocido'
$script:BackupPrivEnabled = $false
$script:PSMajor         = $PSVersionTable.PSVersion.Major
$script:Is64Bit         = [Environment]::Is64BitOperatingSystem
$script:CaseRoot        = $null
$script:Paths           = @{}
$script:LogFile         = $null




$script:TsFmt = 'yyyy-MM-ddTHH:mm:ss.fffffffK'

function Get-NowLocalString { (Get-Date).ToString($script:TsFmt) }
function Get-NowUtcString   { (Get-Date).ToUniversalTime().ToString($script:TsFmt) }

$script:CaseTimeZoneInfo = $null
function Get-CaseTimeZoneInfo {
    




    if ($script:CaseTimeZoneInfo) { return $script:CaseTimeZoneInfo }
    $ids = @('Romance Standard Time', 'Europe/Madrid')
    if ($script:TimeZone) { $ids = @($script:TimeZone) + $ids }
    foreach ($id in $ids) {
        try { $script:CaseTimeZoneInfo = [System.TimeZoneInfo]::FindSystemTimeZoneById($id); if ($script:CaseTimeZoneInfo) { return $script:CaseTimeZoneInfo } } catch { }
    }
    
    try { $script:CaseTimeZoneInfo = [System.TimeZoneInfo]::Local } catch { }
    return $script:CaseTimeZoneInfo
}

function ConvertTo-MadridTimeString {
    




    param($DateTime)
    if ($null -eq $DateTime) { return $null }
    try {
        $tz = Get-CaseTimeZoneInfo
        if ($DateTime -is [System.DateTimeOffset]) {
            $local = [System.TimeZoneInfo]::ConvertTime($DateTime, $tz)
            return $local.ToString($script:TsFmt)
        }
        $dt = [datetime]$DateTime
        
        $utc = $(if ($dt.Kind -eq [System.DateTimeKind]::Utc) { $dt } elseif ($dt.Kind -eq [System.DateTimeKind]::Local) { $dt.ToUniversalTime() } else { [System.DateTime]::SpecifyKind($dt, [System.DateTimeKind]::Utc) })
        $local = [System.TimeZoneInfo]::ConvertTimeFromUtc($utc, $tz)
        return $local.ToString($script:TsFmt)
    } catch {
        try { return ([datetime]$DateTime).ToString($script:TsFmt) } catch { return $null }
    }
}

function Get-WinEnvPath {
    





    param([ValidateSet('SystemRoot','ProgramData','ProgramFiles','ProgramFilesX86','SystemDrive')][string]$Name)
    switch ($Name) {
        'SystemRoot'      { if ($env:SystemRoot) { return $env:SystemRoot }; if ($env:windir) { return $env:windir }; return 'C:\Windows' }
        'ProgramData'     { if ($env:ProgramData) { return $env:ProgramData }; return 'C:\ProgramData' }
        'ProgramFiles'    { if (${env:ProgramFiles}) { return ${env:ProgramFiles} }; return 'C:\Program Files' }
        'ProgramFilesX86' { if (${env:ProgramFiles(x86)}) { return ${env:ProgramFiles(x86)} }; return 'C:\Program Files (x86)' }
        'SystemDrive'     { if ($env:SystemDrive) { return $env:SystemDrive }; return 'C:' }
    }
}





function Write-ForensicLog {
    
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR','DEBUG','CMD')][string]$Level = 'INFO'
    )
    $line = '{0} | {1,-5} | {2}' -f (Get-NowUtcString), $Level, $Message
    if ($script:LogFile) {
        try { Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue } catch { }
    }
    switch ($Level) {
        'ERROR' { [void]$script:ErrorLog.Add($line);   Write-Host $line -ForegroundColor Red }
        'WARN'  { [void]$script:WarningLog.Add($line); Write-Host $line -ForegroundColor Yellow }
        'DEBUG' { if ($VerboseLogging) { Write-Host $line -ForegroundColor DarkGray } }
        'CMD'   { if ($VerboseLogging) { Write-Host $line -ForegroundColor Cyan } }
        default { Write-Host $line }
    }
}

function Test-CommandAvailable {
    
    param([Parameter(Mandatory = $true)][string]$Name)
    return [bool](Get-Command -Name $Name -ErrorAction SilentlyContinue)
}

function Get-ExitCodeMeaning {
    
    param($Code)
    try {
        $n = [int64]$Code
        if ($n -lt 0) { $n = $n + 4294967296 }
        $u = [uint32]$n
        $hex = ('0x{0:X8}' -f $u)
        $map = @{
            '0x80070426' = 'servicio requerido no iniciado (ERROR_SERVICE_NOT_ACTIVE), p.ej. Hora de Windows/W32Time parado'
            '0x80070005' = 'acceso denegado'
            '0x80070002' = 'archivo no encontrado'
            '0x80070003' = 'ruta no encontrada'
            '0x80070020' = 'archivo en uso por otro proceso'
            '0x800706BA' = 'servidor RPC no disponible'
            '0x80070422' = 'servicio deshabilitado (ERROR_SERVICE_DISABLED)'
            '0x8007042C' = 'dependencia de servicio no iniciada'
        }
        if ($map.ContainsKey($hex)) { return ($map[$hex] + ' [' + $hex + ']') }
        if ($Code -eq 1) { return 'error generico de la herramienta' }
        if ($Code -eq 5) { return 'acceso denegado' }
    } catch { }
    return $null
}

function Invoke-NativeTool {
    



    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [string]$Arguments = '',
        [string]$OutputFile = $null,
        [string]$Description = '',
        [int]$TimeoutSeconds = 300
    )
    $cmdString = ('{0} {1}' -f $Executable, $Arguments).Trim()
    Write-ForensicLog -Level CMD -Message ('EXEC: {0}  ({1})' -f $cmdString, $Description)
    $record = New-Object PSObject -Property @{
        TimestampUTC = Get-NowUtcString; Command = $cmdString; Description = $Description
        ExitCode = $null; OutputFile = $OutputFile; Success = $false
    }
    try {
        if (-not (Test-CommandAvailable $Executable)) {
            $record.ExitCode = -1
            Write-ForensicLog -Level WARN -Message ('Herramienta no disponible: {0}' -f $Executable)
            [void]$script:CommandLog.Add($record)
            return $false
        }
        
        
        
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $env:ComSpec
        $inner = $(if ($OutputFile) { ('{0} {1} > "{2}" 2>&1' -f $Executable, $Arguments, $OutputFile) } else { ('{0} {1} > NUL 2>&1' -f $Executable, $Arguments) })
        $psi.Arguments = ('/d /c "{0}"' -f $inner)
        $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
        $psi.RedirectStandardInput = $true   
        $proc = [System.Diagnostics.Process]::Start($psi)
        try { $proc.StandardInput.Close() } catch { }
        $timeoutMs = [int]($TimeoutSeconds * 1000)
        if (-not $proc.WaitForExit($timeoutMs)) {
            try { $proc.Kill() } catch { }
            try { & taskkill.exe /F /T /PID $proc.Id 2>$null | Out-Null } catch { }
            $record.ExitCode = -998
            Write-ForensicLog -Level WARN -Message ('TIMEOUT ({0} s) - proceso terminado: {1}' -f $TimeoutSeconds, $cmdString)
            [void]$script:CommandLog.Add($record)
            return $false
        }
        $proc.WaitForExit()
        $ec = $proc.ExitCode
        $record.ExitCode = $ec
        $record.Success  = ($ec -eq 0)
        if ($ec -ne 0) {
            $why = Get-ExitCodeMeaning -Code $ec
            Write-ForensicLog -Level WARN -Message ('Exit code {0}{1}: {2}' -f $ec, $(if ($why) { ' (' + $why + ')' } else { '' }), $cmdString)
        }
    } catch {
        $record.ExitCode = -999
        Write-ForensicLog -Level ERROR -Message ('Fallo ejecutando "{0}": {1}' -f $cmdString, $_.Exception.Message)
    }
    [void]$script:CommandLog.Add($record)
    return $record.Success
}

function Get-EvidenceFileHash {
    
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [ValidateSet('SHA256','SHA512')][string]$Algorithm = 'SHA256'
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    try {
        $size = (Get-Item -LiteralPath $Path -Force).Length
        if ($size -gt $MaximumFileSizeForHashing) { return 'NOT_COMPUTED_SIZE_LIMIT' }
    } catch { }
    if (Test-CommandAvailable 'Get-FileHash') {
        try { return (Get-FileHash -LiteralPath $Path -Algorithm $Algorithm -ErrorAction Stop).Hash } catch { }
    }
    
    try {
        $out = & certutil.exe -hashfile $Path $Algorithm 2>$null
        if ($LASTEXITCODE -eq 0 -and $out) {
            foreach ($ln in $out) {
                $clean = ($ln -replace '\s','')
                if ($clean -match '^[0-9a-fA-F]{64,128}$') { return $clean.ToUpper() }
            }
        }
    } catch { }
    return $null
}







$script:HashPool = $null
$script:HashJobs = New-Object System.Collections.ArrayList
$script:HashWorkers = [Math]::Max(2, [Math]::Min(8, [Environment]::ProcessorCount))
$script:HashScript = {
    param($Path, $Algorithm, $MaxBytes)
    try {
        $fi = New-Object System.IO.FileInfo($Path)
        if (-not $fi.Exists) { return $null }
        if ($MaxBytes -gt 0 -and $fi.Length -gt $MaxBytes) { return 'NOT_COMPUTED_SIZE_LIMIT' }
        $alg = $(if ($Algorithm -eq 'SHA512') { [System.Security.Cryptography.SHA512]::Create() } else { [System.Security.Cryptography.SHA256]::Create() })
        $fs = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite, 4194304)
        try { $h = $alg.ComputeHash($fs) } finally { $fs.Dispose(); $alg.Dispose() }
        return ([System.BitConverter]::ToString($h) -replace '-','')
    } catch { return $null }
}
function Start-HashPool {
    if ($script:HashPool) { return }
    try {
        $script:HashPool = [runspacefactory]::CreateRunspacePool(1, $script:HashWorkers)
        $script:HashPool.Open()
    } catch { $script:HashPool = $null }
}
function Add-HashJob {
    
    param($Record, [string]$Algorithm = 'SHA256')
    if (-not $script:HashPool) { Start-HashPool }
    if (-not $script:HashPool) {
        
        if ($Algorithm -eq 'SHA512') { $Record.SHA512 = Get-EvidenceFileHash -Path $Record.EvidenceFile -Algorithm SHA512 } else { $Record.SHA256 = Get-EvidenceFileHash -Path $Record.EvidenceFile -Algorithm SHA256 }
        return
    }
    $ps = [powershell]::Create()
    $ps.RunspacePool = $script:HashPool
    [void]$ps.AddScript($script:HashScript).AddArgument($Record.EvidenceFile).AddArgument($Algorithm).AddArgument([int64]$MaximumFileSizeForHashing)
    $handle = $ps.BeginInvoke()
    [void]$script:HashJobs.Add(@{ PS=$ps; Handle=$handle; Record=$Record; Alg=$Algorithm })
    
    if (($script:HashJobs.Count % 64) -eq 0) { Receive-HashJobs -OnlyCompleted }
}
function Receive-HashJobs {
    param([switch]$OnlyCompleted)
    $remaining = New-Object System.Collections.ArrayList
    foreach ($j in @($script:HashJobs)) {
        if ($OnlyCompleted -and -not $j.Handle.IsCompleted) { [void]$remaining.Add($j); continue }
        try {
            $res = $j.PS.EndInvoke($j.Handle)
            $val = $(if ($res -and $res.Count -gt 0) { [string]$res[0] } else { $null })
            if ($j.Alg -eq 'SHA512') { $j.Record.SHA512 = $val } else { $j.Record.SHA256 = $val }
        } catch { } finally { try { $j.PS.Dispose() } catch { } }
    }
    $script:HashJobs = $remaining
}
function Wait-HashPool {
    
    if ($script:HashJobs.Count -gt 0) {
        Write-ForensicLog -Message ('Esperando el calculo de {0} hash(es) pendientes en el pool ({1} hilos)...' -f $script:HashJobs.Count, $script:HashWorkers)
        Receive-HashJobs
    }
}
function Stop-HashPool { try { Wait-HashPool; if ($script:HashPool) { $script:HashPool.Close(); $script:HashPool.Dispose(); $script:HashPool = $null } } catch { } }
function Get-FileHashParallel {
    
    param([string[]]$Paths, [string]$Algorithm = 'SHA256')
    $result = @{}
    if (-not $Paths -or $Paths.Count -eq 0) { return $result }
    $pool = $null
    try { $pool = [runspacefactory]::CreateRunspacePool(1, $script:HashWorkers); $pool.Open() } catch { $pool = $null }
    if (-not $pool) { foreach ($p in $Paths) { $result[$p] = Get-EvidenceFileHash -Path $p -Algorithm $Algorithm }; return $result }
    $jobs = New-Object System.Collections.ArrayList
    foreach ($p in $Paths) {
        $ps = [powershell]::Create(); $ps.RunspacePool = $pool
        [void]$ps.AddScript($script:HashScript).AddArgument($p).AddArgument($Algorithm).AddArgument([int64]$MaximumFileSizeForHashing)
        [void]$jobs.Add(@{ PS=$ps; Handle=$ps.BeginInvoke(); Path=$p })
    }
    foreach ($j in $jobs) {
        try { $r = $j.PS.EndInvoke($j.Handle); $result[$j.Path] = $(if ($r -and $r.Count -gt 0) { [string]$r[0] } else { $null }) } catch { $result[$j.Path] = $null } finally { try { $j.PS.Dispose() } catch { } }
    }
    try { $pool.Close(); $pool.Dispose() } catch { }
    return $result
}

function Register-Evidence {
    



    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Path,
        [Parameter(Mandatory = $true)][string]$Category,
        [string]$SourceDescription = '',
        [string]$Notes = ''
    )
    if ([string]::IsNullOrEmpty($Path) -or -not (Test-Path -LiteralPath $Path)) { return }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if (-not $item -or $item.PSIsContainer) { return }
    $sha256 = $null; $sha512 = $null
    $rec = New-Object PSObject -Property @{
        AcquisitionId   = $script:AcquisitionId
        EvidenceFile    = $Path
        RelativePath    = $Path.Replace($script:CaseRoot, '').TrimStart('\')
        Category        = $Category
        Source          = $SourceDescription
        SizeBytes       = $item.Length
        AcquiredUTC     = Get-NowUtcString
        AcquiredLocal   = Get-NowLocalString
        SHA256          = $sha256
        SHA512          = $sha512
        VerifiedAtEnd   = $null
        Notes           = $Notes
    }
    [void]$script:EvidenceList.Add($rec)
    if ($IncludeHashes) {
        
        Add-HashJob -Record $rec -Algorithm 'SHA256'
        if ($HashAlgorithms -contains 'SHA512') { Add-HashJob -Record $rec -Algorithm 'SHA512' }
    }
    Write-ForensicLog -Level DEBUG -Message ('Evidencia registrada: {0} ({1} bytes) [hash en cola]' -f $rec.RelativePath, $rec.SizeBytes)
}

function Get-ArtifactStatus {
    





    param([string]$Reason)
    $r = ([string]$Reason).ToLowerInvariant()
    if ($r -match 'no instalad|not installed|componente no instalado|sysmon no|openssh no') { return 'NOT_INSTALLED' }
    if ($r -match 'no aplica|not applicable|no aplicable|habitual en windows server|no pertenece a esta version|edicion') { return 'NOT_APPLICABLE' }
    if ($r -match 'sin eventos|0 eventos|vacio|vacia|sin resultados|no contiene eventos|sin registros|no se encontraron eventos|no se hallaron|no aportaron|no se localizaron comandos|no events') { return 'EMPTY' }
    if ($r -match 'no se hallo herramienta|herramienta no (presente|disponible)|no hay un registro de eventos|no se localizaron instalaciones') { return 'NOT_INSTALLED' }
    if ($r -match 'deshabilitad|disabled|auditoria.*desactivad|desactivada') { return 'DISABLED' }
    if ($r -match 'no existe|no encontrad|not found|no presente|la ruta no existe') { return 'NOT_FOUND' }
    if ($r -match 'acceso denegado|access denied|privilegios de admin|no esta elevada|requiere admin|sin admin') { return 'ACCESS_DENIED' }
    if ($r -match 'bloquead|locked|en uso') { return 'LOCKED' }
    if ($r -match 'imagen (forense|offline)|analizada offline|imagen de disco|necesidad de imagen') { return 'REQUIRES_OFFLINE_ACQUISITION' }
    if ($r -match 'controlador de dominio|active directory|firewall perimetral|fuente externa|servidor de correo|router|vpn') { return 'REQUIRES_EXTERNAL_SOURCE' }
    if ($r -match 'parse|parsing|no se pudo interpretar|formato') { return 'PARSE_FAILED' }
    if ($r -match 'error|fallo|fallida|devolvio error') { return 'ACQUISITION_FAILED' }
    return 'UNAVAILABLE'
}

function Get-ArtifactStatusLabel {
    
    param([string]$Status)
    switch ($Status) {
        'NOT_INSTALLED'                { 'Componente no instalado' ; break }
        'NOT_APPLICABLE'               { 'No aplicable a este sistema' ; break }
        'EMPTY'                        { 'Existe pero sin registros' ; break }
        'DISABLED'                     { 'Presente pero deshabilitado' ; break }
        'NOT_FOUND'                    { 'No encontrado en el sistema' ; break }
        'ACCESS_DENIED'                { 'Acceso denegado (permisos)' ; break }
        'LOCKED'                       { 'Bloqueado (fichero en uso)' ; break }
        'ACQUISITION_FAILED'           { 'Fallo de adquisicion' ; break }
        'PARSE_FAILED'                 { 'Fallo de interpretacion' ; break }
        'REQUIRES_OFFLINE_ACQUISITION' { 'Requiere imagen/analisis offline' ; break }
        'REQUIRES_EXTERNAL_SOURCE'     { 'Requiere fuente externa (DC/firewall/VPN)' ; break }
        default                        { 'No disponible' }
    }
}

function Register-MissingEvidence {
    
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Evidence,
        [Parameter(Mandatory = $true)][string]$Reason,
        [string]$Status = $null
    )
    if (-not $Status) { $Status = Get-ArtifactStatus -Reason $Reason }
    $rec = New-Object PSObject -Property @{
        TimestampUTC = Get-NowUtcString; Evidence = $Evidence; Reason = $Reason
        Status = $Status; StatusLabel = (Get-ArtifactStatusLabel -Status $Status)
    }
    [void]$script:MissingEvidence.Add($rec)
    
    $benign = @('NOT_INSTALLED','NOT_APPLICABLE','EMPTY','DISABLED','NOT_FOUND','REQUIRES_OFFLINE_ACQUISITION','REQUIRES_EXTERNAL_SOURCE')
    if ($benign -contains $Status) {
        Write-ForensicLog -Level INFO -Message ('[{0}] {1} -> {2}' -f $Status, $Evidence, $Reason)
    } else {
        Write-ForensicLog -Level WARN -Message ('[{0}] {1} -> {2}' -f $Status, $Evidence, $Reason)
    }
}

function Register-Source {
    param([string]$Source)
    if ($script:SourcesQueried -notcontains $Source) { [void]$script:SourcesQueried.Add($Source) }
}

function Test-FileInUse {
    
    param([string]$Path)
    try {
        $p = $Path; if ($p.Length -ge 248 -and -not $p.StartsWith('\\?\')) { $p = '\\?\' + $p }
        $fs = [System.IO.File]::Open($p, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $fs.Close(); return $false
    } catch [System.IO.IOException] {
        $hr = $_.Exception.HResult -band 0xFFFF
        if ($hr -eq 32 -or $hr -eq 33) { return $true }   
        return $false
    } catch { return $false }
}

function Get-ShortDestinationPath {
    




    param([string]$DestinationPath, [int]$MaxLen = 240)
    if ($DestinationPath.Length -le $MaxLen) { return $DestinationPath }
    $dir = Split-Path -Path $DestinationPath -Parent
    $leaf = Split-Path -Path $DestinationPath -Leaf
    $ext = [System.IO.Path]::GetExtension($leaf)
    $md5 = [System.Security.Cryptography.MD5]::Create()
    $h = ([System.BitConverter]::ToString($md5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($leaf))) -replace '-','').Substring(0,10)
    $room = $MaxLen - $dir.Length - 1 - $ext.Length - 12
    if ($room -lt 8) { $room = 8 }
    $base = [System.IO.Path]::GetFileNameWithoutExtension($leaf)
    if ($base.Length -gt $room) { $base = $base.Substring(0, $room) }
    return (Join-Path $dir ($base + '~' + $h + $ext))
}

$script:LockedSkipStats = @{ Skipped = 0 }
function Copy-EvidenceFile {
    








    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$SourcePath,
        [Parameter(Mandatory = $true)][string]$DestinationPath,
        [string]$Category = 'FileSystem',
        [string]$Notes = ''
    )
    if ([string]::IsNullOrEmpty($SourcePath) -or -not (Test-Path -LiteralPath $SourcePath)) {
        $evName = $SourcePath; if (-not $evName) { $evName = '(ruta vacia)' }
        Register-MissingEvidence -Evidence $evName -Reason 'La ruta no existe en el sistema' -Status 'NOT_FOUND'
        return $false
    }
    
    
    try {
        $attrs = [System.IO.File]::GetAttributes($SourcePath)
        $isCloud = (([int]$attrs -band 0x400000) -ne 0) -or (([int]$attrs -band 0x40000) -ne 0) -or (([int]$attrs -band 0x1000) -ne 0)  
        if ($isCloud) {
            Register-MissingEvidence -Evidence $SourcePath -Reason 'Archivo de nube no descargado (placeholder OneDrive/Files On-Demand): el contenido no reside en el disco local; no se fuerza su descarga.' -Status 'REQUIRES_EXTERNAL_SOURCE'
            return $false
        }
    } catch { }
    
    $origLeaf = Split-Path -Path $DestinationPath -Leaf
    $DestinationPath = Get-ShortDestinationPath -DestinationPath $DestinationPath
    if ((Split-Path -Path $DestinationPath -Leaf) -ne $origLeaf) { $Notes = (('{0} [nombre de destino acortado; nombre original: {1}]' -f $Notes, $origLeaf)).Trim() }
    $destDir = Split-Path -Path $DestinationPath -Parent
    if (-not (Test-Path -LiteralPath $destDir)) {
        try { New-Item -Path $destDir -ItemType Directory -Force -ErrorAction Stop | Out-Null } catch { }
    }
    
    $srcP = $SourcePath; $dstP = $DestinationPath
    $long = ($srcP.Length -ge 248 -or $dstP.Length -ge 248)
    if ($long) {
        if (-not $srcP.StartsWith('\\?\')) { $srcP = '\\?\' + $srcP }
        if (-not $dstP.StartsWith('\\?\')) { $dstP = '\\?\' + $dstP }
    }
    $copyErr = $null
    $isWin = ($env:OS -eq 'Windows_NT') -or ([System.IO.Path]::DirectorySeparatorChar -eq '\\')
    if (-not $isWin) { $long = $false; $srcP = $SourcePath; $dstP = $DestinationPath }   
    try {
        if ($long) { [System.IO.File]::Copy($srcP, $dstP, $true) }
        else { Copy-Item -LiteralPath $SourcePath -Destination $DestinationPath -Force -ErrorAction Stop }
        Register-Evidence -Path $DestinationPath -Category $Category -SourceDescription $SourcePath -Notes $Notes
        return $true
    } catch { $copyErr = $_.Exception.Message }
    
    if ($copyErr) {
        try {
            [System.IO.File]::Copy($SourcePath, $DestinationPath, $true)
            Register-Evidence -Path $DestinationPath -Category $Category -SourceDescription $SourcePath -Notes $Notes
            return $true
        } catch { $copyErr = $_.Exception.Message }
    }
    
    if ($isWin -and $copyErr -match '(?i)path.*long|demasiado larg|PathTooLong|nombre de archivo o la extensi|filename or extension|not supported|no se admite') {
        try {
            $s2 = $(if ($SourcePath.StartsWith('\\?\')) { $SourcePath } else { '\\?\' + $SourcePath })
            $d2 = $(if ($DestinationPath.StartsWith('\\?\')) { $DestinationPath } else { '\\?\' + $DestinationPath })
            [System.IO.File]::Copy($s2, $d2, $true)
            Register-Evidence -Path $DestinationPath -Category $Category -SourceDescription $SourcePath -Notes (('{0} [copiado con ruta larga \\?\]' -f $Notes).Trim())
            return $true
        } catch { $copyErr = $_.Exception.Message }
    }
    
    $inUse = Test-FileInUse -Path $SourcePath
    if (-not $inUse) {
        
        $st = $(if ($copyErr -match '(?i)denegado|denied|unauthorized') { 'ACCESS_DENIED' } else { 'ACQUISITION_FAILED' })
        Register-MissingEvidence -Evidence $SourcePath -Reason ('Copia fallida (no por bloqueo): {0}' -f $copyErr) -Status $st
        return $false
    }
    
    $snap = New-CaseSnapshot
    if ($snap) {
        try {
            $rel = $SourcePath
            if ($rel -match '^[A-Za-z]:\\') { $rel = $rel.Substring(2) }
            $snapSrc = ($snap.TrimEnd('\') + $rel)
            if ($snapSrc.Length -ge 248) { $snapSrc = '\\?\' + $snapSrc }
            $d3 = $(if ($DestinationPath.Length -ge 248) { '\\?\' + $DestinationPath } else { $DestinationPath })
            [System.IO.File]::Copy($snapSrc, $d3, $true)
            Register-Evidence -Path $DestinationPath -Category $Category -SourceDescription $SourcePath -Notes (('{0} [copiado desde instantanea VSS de la ejecucion por estar en uso]' -f $Notes).Trim())
            return $true
        } catch { Write-ForensicLog -Level DEBUG -Message ('Copia desde instantanea fallida para {0}: {1}' -f $SourcePath, $_.Exception.Message) }
    }
    
    $critical = ($SourcePath -match '(?i)\\(NTUSER\.DAT|UsrClass\.dat|SAM|SECURITY|SOFTWARE|SYSTEM|Amcache\.hve|SRUDB\.dat|WebCacheV01\.dat|DEFAULT)$|\.evtx$|\.edb$|\.hve$|\.jfm$|\.log1?$')
    if ($critical -and $script:IsAdmin -and (Test-CommandAvailable 'esentutl.exe')) {
        $ok = Invoke-NativeTool -Executable 'esentutl.exe' `
            -Arguments ('/y "{0}" /vss /d "{1}"' -f $SourcePath, $DestinationPath) `
            -Description ('Copia VSS (esentutl) de archivo critico bloqueado: {0}' -f $SourcePath)
        if ($ok -and (Test-Path -LiteralPath $DestinationPath)) {
            Register-Evidence -Path $DestinationPath -Category $Category -SourceDescription $SourcePath -Notes (('{0} [copiado via esentutl /vss por bloqueo]' -f $Notes).Trim())
            return $true
        }
        Register-MissingEvidence -Evidence $SourcePath -Reason 'Archivo critico bloqueado; copia directa, instantanea VSS y esentutl /vss fallidas (requiere imagen offline)' -Status 'REQUIRES_OFFLINE_ACQUISITION'
        return $false
    }
    
    $script:LockedSkipStats.Skipped++
    Register-MissingEvidence -Evidence $SourcePath -Reason 'Archivo en uso (bloqueado) no critico; no se escala a esentutl para no demorar la adquisicion. Recuperable desde imagen offline si fuese necesario.' -Status 'LOCKED'
    return $false
}

function New-CaseSnapshot {
    





    if ($script:SnapshotDevice) { return $script:SnapshotDevice }
    if ($script:SnapshotTried) { return $null }
    $script:SnapshotTried = $true
    if (-not $script:IsAdmin) { return $null }
    $vol = $(if ($env:SystemDrive) { $env:SystemDrive + '\' } else { 'C:\' })
    try {
        $cls = [wmiclass]'root\cimv2:Win32_ShadowCopy'
        $res = $cls.Create($vol, 'ClientAccessible')
        if ($res -and $res.ReturnValue -eq 0 -and $res.ShadowID) {
            $sc = Get-WmiObject -Class Win32_ShadowCopy -ErrorAction SilentlyContinue | Where-Object { $_.ID -eq $res.ShadowID }
            if ($sc -and $sc.DeviceObject) {
                $script:SnapshotDevice = $sc.DeviceObject
                $script:SnapshotId = $res.ShadowID
                Write-ForensicLog -Message ('Instantanea VSS creada para copia congelada de ficheros en uso: {0}' -f $script:SnapshotDevice)
                return $script:SnapshotDevice
            }
        }
        Write-ForensicLog -Level WARN -Message ('No se pudo crear instantanea VSS (ReturnValue={0}); los ficheros en uso se copiaran en vivo y se marcaran como volatiles.' -f $(if ($res) { $res.ReturnValue } else { 'n/d' }))
    } catch {
        Write-ForensicLog -Level WARN -Message ('Creacion de instantanea VSS fallida: {0}. Los ficheros en uso se marcaran como volatiles.' -f $_.Exception.Message)
    }
    return $null
}

function Remove-CaseSnapshot {
    if ($script:SnapshotId) {
        try {
            $sc = Get-WmiObject -Class Win32_ShadowCopy -ErrorAction SilentlyContinue | Where-Object { $_.ID -eq $script:SnapshotId }
            if ($sc) { $sc.Delete(); Write-ForensicLog -Message 'Instantanea VSS liberada.' }
        } catch { }
        $script:SnapshotId = $null; $script:SnapshotDevice = $null
    }
}

function Copy-EvidenceFileFrozen {
    





    param(
        [Parameter(Mandatory = $true)][string]$SourcePath,
        [Parameter(Mandatory = $true)][string]$DestinationPath,
        [string]$Category = 'RemoteAccess',
        [string]$Notes = ''
    )
    if (-not (Test-Path -LiteralPath $SourcePath)) {
        Register-MissingEvidence -Evidence $SourcePath -Reason 'La ruta no existe en el sistema'
        return $false
    }
    $destDir = Split-Path -Path $DestinationPath -Parent
    if (-not (Test-Path -LiteralPath $destDir)) { New-Item -Path $destDir -ItemType Directory -Force | Out-Null }

    $dev = New-CaseSnapshot
    if ($dev) {
        
        $qualifier = $null
        try { $qualifier = [System.IO.Path]::GetPathRoot($SourcePath) } catch { }
        if ($qualifier) {
            $rel = $SourcePath.Substring($qualifier.Length)
            $snapSrc = ($dev.TrimEnd('\') + '\' + $rel)
            try {
                Copy-Item -LiteralPath $snapSrc -Destination $DestinationPath -Force -ErrorAction Stop
                Register-Evidence -Path $DestinationPath -Category $Category -SourceDescription $SourcePath -Notes (('{0} [copia CONGELADA desde instantanea VSS]' -f $Notes).Trim())
                return $true
            } catch {
                Write-ForensicLog -Level DEBUG -Message ('Copia desde instantanea fallo para {0}: {1}. Se copia en vivo (volatil).' -f $SourcePath, $_.Exception.Message)
            }
        }
    }
    
    try {
        Copy-Item -LiteralPath $SourcePath -Destination $DestinationPath -Force -ErrorAction Stop
        $ev = Register-Evidence -Path $DestinationPath -Category $Category -SourceDescription $SourcePath -Notes (('{0} [FICHERO EN USO: contenido volatil durante la adquisicion; sin instantanea VSS disponible]' -f $Notes).Trim())
        if ($null -ne $script:VolatileEvidence) { [void]$script:VolatileEvidence.Add($DestinationPath) }
        return $true
    } catch {
        Register-MissingEvidence -Evidence $SourcePath -Reason 'Fichero en uso y sin instantanea VSS; copia en vivo fallida'
        return $false
    }
}

function Save-SystemHive {
    










    param(
        [Parameter(Mandatory = $true)][string]$Key,
        [Parameter(Mandatory = $true)][string]$Dest,
        [string]$ConfigFile = $null
    )
    if (-not $script:IsAdmin) {
        Register-MissingEvidence -Evidence $Key -Reason 'La sesion NO esta elevada: relance PowerShell como administrador (reg save y copia VSS requieren token elevado).'
        return $false
    }
    
    $ok = Invoke-NativeTool -Executable 'reg.exe' -Arguments ('save "{0}" "{1}" /y' -f $Key, $Dest) -Description ('reg save de {0}' -f $Key)
    if ($ok -and (Test-Path -LiteralPath $Dest)) {
        Register-Evidence -Path $Dest -Category 'Registry' -SourceDescription $Key -Notes 'Copia nativa reg save (formato hive)'
        return $true
    }
    
    if ($ConfigFile -and (Test-Path -LiteralPath $ConfigFile) -and (Test-CommandAvailable 'esentutl.exe')) {
        Write-ForensicLog -Level WARN -Message ('reg save de {0} no disponible; intentando copia cruda VSS de {1}' -f $Key, $ConfigFile)
        $okv = Invoke-NativeTool -Executable 'esentutl.exe' -Arguments ('/y "{0}" /vss /d "{1}"' -f $ConfigFile, $Dest) -Description ('Copia VSS de hive {0}' -f $Key)
        if ($okv -and (Test-Path -LiteralPath $Dest)) {
            Register-Evidence -Path $Dest -Category 'Registry' -SourceDescription $ConfigFile -Notes ('Hive {0} via copia cruda VSS (reg save denegado)' -f $Key)
            return $true
        }
    }
    
    Register-MissingEvidence -Evidence $Key -Reason ('Elevado, pero acceso denegado en reg save y en copia VSS. Causa probable: bloqueo por antivirus/EDR, reglas ASR (robo de credenciales) o Credential Guard, o hive especialmente protegida. Recomendacion: obtener {0} de una imagen forense de disco o de una instantanea VSS analizada offline.' -f $Key)
    return $false
}

function Export-ObjectData {
    
    param(
        [Parameter(Mandatory = $true)][AllowNull()]$Data,
        [Parameter(Mandatory = $true)][string]$BaseName,
        [string]$Category = 'Parsed'
    )
    if ($null -eq $Data) { return }
    $arr = @($Data)
    if ($arr.Count -eq 0) { return }
    $csv  = Join-Path $script:Paths.ParsedCSV  ($BaseName + '.csv')
    $json = Join-Path $script:Paths.ParsedJSON ($BaseName + '.json')
    try {
        $arr | Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8
        Register-Evidence -Path $csv -Category $Category -SourceDescription $BaseName
    } catch {
        Write-ForensicLog -Level ERROR -Message ('Error exportando CSV {0}: {1}' -f $BaseName, $_.Exception.Message)
    }
    try {
        $depth = 6
        $jsonText = $arr | ConvertTo-Json -Depth $depth
        [System.IO.File]::WriteAllText($json, $jsonText, (New-Object System.Text.UTF8Encoding($false)))
        Register-Evidence -Path $json -Category $Category -SourceDescription $BaseName
    } catch {
        Write-ForensicLog -Level ERROR -Message ('Error exportando JSON {0}: {1}' -f $BaseName, $_.Exception.Message)
    }
}

function Get-CimOrWmi {
    
    param(
        [Parameter(Mandatory = $true)][string]$ClassName,
        [string]$Filter = $null,
        [string]$Namespace = 'root\cimv2'
    )
    try {
        if (Test-CommandAvailable 'Get-CimInstance') {
            if ($Filter) { return Get-CimInstance -ClassName $ClassName -Filter $Filter -Namespace $Namespace -ErrorAction Stop }
            return Get-CimInstance -ClassName $ClassName -Namespace $Namespace -ErrorAction Stop
        }
    } catch {
        Write-ForensicLog -Level DEBUG -Message ('CIM fallo para {0}: {1}' -f $ClassName, $_.Exception.Message)
    }
    try {
        if (Test-CommandAvailable 'Get-WmiObject') {
            if ($Filter) { return Get-WmiObject -Class $ClassName -Filter $Filter -Namespace $Namespace -ErrorAction Stop }
            return Get-WmiObject -Class $ClassName -Namespace $Namespace -ErrorAction Stop
        }
    } catch {
        Write-ForensicLog -Level DEBUG -Message ('WMI fallo para {0}: {1}' -f $ClassName, $_.Exception.Message)
    }
    return $null
}





function Get-ProcessElevation {
    






    $o = New-Object PSObject -Property @{
        IsElevated = $false; InAdminGroup = $false; IntegrityLevel = 'Desconocido'; UserName = $null
    }
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $o.UserName = $id.Name
        $pr = New-Object Security.Principal.WindowsPrincipal($id)
        
        $o.IsElevated = $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        
        $adminSidVal = (New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')).Value
        foreach ($g in $id.Groups) {
            try { if ($g.Value -eq $adminSidVal) { $o.InAdminGroup = $true; break } } catch { }
        }
        $o.IntegrityLevel = $(if ($o.IsElevated) { 'Alto (elevado)' } else { 'Medio (no elevado)' })
    } catch { }
    return $o
}

$script:PrivHelperReady = $false
function Enable-ProcessPrivilege {
    





    param([Parameter(Mandatory = $true)][string]$Privilege)
    if (-not $script:PrivHelperReady -and ('ForensicPriv.Tokens' -as [type])) { $script:PrivHelperReady = $true }
    if (-not $script:PrivHelperReady) {
        try {
            Add-Type -Namespace ForensicPriv -Name Tokens -ErrorAction Stop -MemberDefinition @'
[DllImport("advapi32.dll", SetLastError=true)]
static extern bool OpenProcessToken(IntPtr h, uint acc, out IntPtr tok);
[DllImport("advapi32.dll", SetLastError=true)]
static extern bool LookupPrivilegeValue(string host, string name, out long luid);
[DllImport("advapi32.dll", SetLastError=true)]
static extern bool AdjustTokenPrivileges(IntPtr tok, bool dis, ref TOKPRIV1LUID newst, int len, IntPtr prev, IntPtr relen);
[DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
[StructLayout(LayoutKind.Sequential, Pack=1)] public struct TOKPRIV1LUID { public int Count; public long Luid; public int Attr; }
const int SE_PRIVILEGE_ENABLED = 0x00000002;
const uint TOKEN_ADJUST_PRIVILEGES = 0x00000020;
const uint TOKEN_QUERY = 0x00000008;
public static bool Enable(string priv) {
    IntPtr tok;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out tok)) return false;
    TOKPRIV1LUID tp; tp.Count = 1; tp.Luid = 0; tp.Attr = SE_PRIVILEGE_ENABLED;
    if (!LookupPrivilegeValue(null, priv, out tp.Luid)) return false;
    bool ok = AdjustTokenPrivileges(tok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
    return ok && (System.Runtime.InteropServices.Marshal.GetLastWin32Error() == 0);
}
'@
            $script:PrivHelperReady = $true
        } catch {
            Write-ForensicLog -Level DEBUG -Message ('No se pudo preparar el ayudante de privilegios: {0}' -f $_.Exception.Message)
            return $false
        }
    }
    try { return [bool][ForensicPriv.Tokens]::Enable($Privilege) } catch { return $false }
}

function Disable-QuickEditMode {
    





    try {
        if (-not ('WinConsole.QuickEdit' -as [type])) {
            Add-Type -Namespace WinConsole -Name QuickEdit -ErrorAction Stop -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr GetStdHandle(int handle);
[DllImport("kernel32.dll", SetLastError=true)] public static extern bool GetConsoleMode(IntPtr h, out uint mode);
[DllImport("kernel32.dll", SetLastError=true)] public static extern bool SetConsoleMode(IntPtr h, uint mode);
'@
        }
        $STD_INPUT_HANDLE = -10
        $ENABLE_EXTENDED_FLAGS = [uint32]0x0080
        $ENABLE_QUICK_EDIT_MODE = [uint32]0x0040
        $h = [WinConsole.QuickEdit]::GetStdHandle($STD_INPUT_HANDLE)
        $mode = [uint32]0
        if ([WinConsole.QuickEdit]::GetConsoleMode($h, [ref]$mode)) {
            $newMode = ($mode -band (-bnot $ENABLE_QUICK_EDIT_MODE)) -bor $ENABLE_EXTENDED_FLAGS
            if ([WinConsole.QuickEdit]::SetConsoleMode($h, $newMode)) { return $true }
        }
    } catch { }
    return $false
}

$script:Heartbeat = [hashtable]::Synchronized(@{ Module = 'inicio'; Since = (Get-Date); Stop = $false; LastBeat = (Get-Date) })
$script:HeartbeatPS = $null; $script:HeartbeatHandle = $null; $script:HeartbeatRunspace = $null
function Start-Heartbeat {
    





    try {
        if ($script:HeartbeatPS) { return }
        $rs = [runspacefactory]::CreateRunspace()
        $rs.ApartmentState = 'MTA'; $rs.ThreadOptions = 'ReuseThread'
        $rs.Open()
        $rs.SessionStateProxy.SetVariable('HB', $script:Heartbeat)
        $ps = [powershell]::Create(); $ps.Runspace = $rs
        [void]$ps.AddScript({
            $ENABLE_EXTENDED_FLAGS = [uint32]0x0080; $ENABLE_QUICK_EDIT_MODE = [uint32]0x0040
            $t = 0
            while (-not $HB.Stop) {
                Start-Sleep -Milliseconds 500; $t += 500
                if ($t -lt 30000) { continue }
                $t = 0
                try {
                    $mins = [int]([math]::Round(((Get-Date) - $HB.Since).TotalMinutes))
                    [System.Console]::Error.WriteLine(('   [latido {0}] trabajando... modulo: {1} ({2} min en este modulo). No haga clic en la ventana; Ctrl+C aborta.' -f (Get-Date).ToString('HH:mm:ss'), $HB.Module, $mins))
                    if ('WinConsole.QuickEdit' -as [type]) {
                        $hd = [WinConsole.QuickEdit]::GetStdHandle(-10); $mode = [uint32]0
                        if ([WinConsole.QuickEdit]::GetConsoleMode($hd, [ref]$mode)) {
                            if ($mode -band $ENABLE_QUICK_EDIT_MODE) { [void][WinConsole.QuickEdit]::SetConsoleMode($hd, (($mode -band (-bnot $ENABLE_QUICK_EDIT_MODE)) -bor $ENABLE_EXTENDED_FLAGS)) }
                        }
                    }
                    $HB.LastBeat = Get-Date
                } catch { }
            }
        })
        $script:HeartbeatRunspace = $rs; $script:HeartbeatPS = $ps
        $script:HeartbeatHandle = $ps.BeginInvoke()
    } catch { }
}
function Stop-Heartbeat {
    try {
        $script:Heartbeat.Stop = $true
        if ($script:HeartbeatPS) {
            try { [void]$script:HeartbeatHandle.AsyncWaitHandle.WaitOne(2000) } catch { }
            try { $script:HeartbeatPS.Stop() } catch { }
            try { $script:HeartbeatPS.Dispose() } catch { }
            try { $script:HeartbeatRunspace.Close(); $script:HeartbeatRunspace.Dispose() } catch { }
            $script:HeartbeatPS = $null; $script:HeartbeatRunspace = $null; $script:HeartbeatHandle = $null
        }
    } catch { }
}
function Set-HeartbeatModule { param([string]$Name) try { $script:Heartbeat.Module = $Name; $script:Heartbeat.Since = Get-Date } catch { } }

function Initialize-Environment {
    
    $qe = Disable-QuickEditMode
    Start-Heartbeat
    
    $script:Elevation = Get-ProcessElevation
    $script:IsAdmin   = $script:Elevation.IsElevated

    
    
    if ($FleetRoot) {
        $fleetClean = $FleetRoot.TrimEnd('\', '/')
        if ($fleetClean -match '^[A-Za-z]:$') { $fleetClean = $fleetClean + '\' }   
        $script:OutputPath = Join-Path $fleetClean 'ordenadores'
        if (-not $script:CaseId) {
            $cn = $env:COMPUTERNAME
            if (-not $cn) { try { $cn = [System.Net.Dns]::GetHostName() } catch { } }
            if (-not $cn) { $cn = 'EQUIPO_DESCONOCIDO' }
            $script:CaseId = ($cn -replace '[^A-Za-z0-9._-]', '_')
        }
    } else {
        $script:OutputPath = $OutputPath
        $script:CaseId = $CaseId
    }
    if (-not $script:OutputPath -or -not $script:CaseId) {
        throw 'Debe indicar -CaseId y -OutputPath, o bien -FleetRoot (modo flota: <FleetRoot>\ordenadores\<EQUIPO>).'
    }
    if (-not (Test-Path -LiteralPath $script:OutputPath)) { New-Item -ItemType Directory -Path $script:OutputPath -Force | Out-Null }
    $script:CaseRoot = Join-Path $script:OutputPath $script:CaseId
    $dirs = @{
        Meta        = '00_Case_Metadata'
        AcqLogs     = '01_Acquisition_Logs'
        RawEvt      = '02_Raw_Evidence\EventLogs'
        RawReg      = '02_Raw_Evidence\Registry'
        RawFS       = '02_Raw_Evidence\FileSystem'
        RawRemote   = '02_Raw_Evidence\RemoteAccess'
        RawNet      = '02_Raw_Evidence\Network'
        RawUsers    = '02_Raw_Evidence\Users'
        RawPersist  = '02_Raw_Evidence\Persistence'
        RawSec      = '02_Raw_Evidence\SecurityTools'
        RawDeleted  = '02_Raw_Evidence\DeletedFiles'
        ParsedCSV   = '03_Parsed_Evidence\CSV'
        ParsedJSON  = '03_Parsed_Evidence\JSON'
        ParsedTXT   = '03_Parsed_Evidence\TXT'
        ParsedHTML  = '03_Parsed_Evidence\HTML'
        Hashes      = '04_Hashes'
        Timeline    = '05_Timeline'
        Report      = '06_Report'
        Errors      = '07_Errors'
        ToolInfo    = '08_Tool_Information'
    }
    foreach ($k in $dirs.Keys) {
        $p = Join-Path $script:CaseRoot $dirs[$k]
        New-Item -Path $p -ItemType Directory -Force | Out-Null
        $script:Paths[$k] = $p
    }
    $script:LogFile = Join-Path $script:Paths.AcqLogs ('acquisition_{0}.log' -f $script:AcquisitionId)

    
    if (Test-CommandAvailable 'Start-Transcript') {
        try {
            Start-Transcript -Path (Join-Path $script:Paths.AcqLogs ('transcript_{0}.txt' -f $script:AcquisitionId)) -ErrorAction SilentlyContinue | Out-Null
        } catch { }
    }

    Write-ForensicLog -Message ('=== INICIO ADQUISICION {0} ===' -f $script:AcquisitionId)
    if ($Examiner -eq '(no indicado)' -or $Organization -eq '(no indicado)') {
        Write-ForensicLog -Level WARN -Message 'AVISO: no se indico -Examiner y/o -Organization. Para un peritaje formal, indiquelos (constan en la cadena de custodia). La adquisicion continua igualmente.'
    }
    Write-ForensicLog -Message ('Caso: {0} | Organizacion: {1} | Investigador: {2}' -f $script:CaseId, $Organization, $Examiner)
    Write-ForensicLog -Message ('Equipo: {0} | Usuario ejecutor: {1}\{2}' -f $env:COMPUTERNAME, $env:USERDOMAIN, $env:USERNAME)
    Write-ForensicLog -Message ('Elevacion real del token: {0} | Miembro de Administradores: {1} | Nivel de integridad: {2}' -f $script:Elevation.IsElevated, $script:Elevation.InAdminGroup, $script:Elevation.IntegrityLevel)
    Write-ForensicLog -Message ('PowerShell {0} | SO 64-bit: {1} | ReadOnlyMode: {2}' -f $PSVersionTable.PSVersion, $script:Is64Bit, $ReadOnlyMode)
    Write-ForensicLog -Message ('Periodo de interes: {0} a {1} (hora local del sistema)' -f $StartDate.ToString($script:TsFmt), $EndDate.ToString($script:TsFmt))
    
    $capList = New-Object System.Collections.ArrayList
    foreach ($c in @('Get-WinEvent','Get-CimInstance','Get-WmiObject','Get-NetTCPConnection','Get-LocalUser','Get-FileHash','Get-MpComputerStatus','Get-ScheduledTask','Get-AuthenticodeSignature')) {
        [void]$capList.Add(('{0}={1}' -f $c, [bool](Get-Command $c -ErrorAction SilentlyContinue)))
    }
    Write-ForensicLog -Message ('Capacidades (PS {0}): {1}' -f $PSVersionTable.PSVersion, ($capList -join ' | '))
    Write-ForensicLog -Message ('Modo de edicion rapida (QuickEdit) de la consola desactivado: {0} (evita pausas por clic/seleccion durante la adquisicion).' -f $qe)

    
    if (-not $script:IsAdmin) {
        $bar = '============================================================'
        Write-Host ''
        Write-Host $bar -ForegroundColor Yellow
        if ($script:Elevation.InAdminGroup) {
            Write-Host '  AVISO: LA SESION NO ESTA ELEVADA (token filtrado por UAC)' -ForegroundColor Yellow
            Write-Host '  Tu cuenta ES administradora, pero este proceso NO se esta' -ForegroundColor Yellow
            Write-Host '  ejecutando como administrador.' -ForegroundColor Yellow
            Write-Host '  ACCION: cierra esta consola y abre PowerShell con boton' -ForegroundColor Yellow
            Write-Host '  derecho > "Ejecutar como administrador", y vuelve a lanzar.' -ForegroundColor Yellow
        } else {
            Write-Host '  AVISO: LA CUENTA NO ES ADMINISTRADORA' -ForegroundColor Yellow
            Write-Host '  ACCION: ejecuta el script con una cuenta administradora,' -ForegroundColor Yellow
            Write-Host '  en una consola elevada ("Ejecutar como administrador").' -ForegroundColor Yellow
        }
        Write-Host '  Sin elevacion NO se adquiriran, entre otros:' -ForegroundColor Yellow
        Write-Host '    - Registro Security.evtx (inicios de sesion, auditoria)' -ForegroundColor Yellow
        Write-Host '    - Hives SAM / SECURITY / SYSTEM / SOFTWARE' -ForegroundColor Yellow
        Write-Host '    - auditpol, SRUM, Amcache, copias VSS de ficheros bloqueados' -ForegroundColor Yellow
        Write-Host '  El script CONTINUARA y adquirira todo lo accesible, dejando' -ForegroundColor Yellow
        Write-Host '  constancia de lo omitido en 07_Errors\missing_evidence.csv.' -ForegroundColor Yellow
        Write-Host $bar -ForegroundColor Yellow
        Write-Host ''
        Write-ForensicLog -Level WARN -Message 'SESION NO ELEVADA: no se adquiriran Security.evtx, hives SAM/SECURITY/SYSTEM/SOFTWARE, auditpol, SRUM, Amcache ni copias VSS. Relance como administrador para una adquisicion completa.'
    } else {
        Write-Host ''
        Write-Host '  [OK] Sesion elevada (token de administrador). Adquisicion completa disponible.' -ForegroundColor Green
        Write-Host ''
        
        $pb = Enable-ProcessPrivilege -Privilege 'SeBackupPrivilege'
        $pr = Enable-ProcessPrivilege -Privilege 'SeRestorePrivilege'
        $ps = Enable-ProcessPrivilege -Privilege 'SeSecurityPrivilege'
        Write-ForensicLog -Message ('Privilegios habilitados en el proceso -> SeBackup: {0} | SeRestore: {1} | SeSecurity: {2}' -f $pb, $pr, $ps)
    }
    if ($TargetComputer -ne $env:COMPUTERNAME) {
        Write-ForensicLog -Level WARN -Message ('TargetComputer={0}: solo la exportacion de eventos via wevtutil /r: es remota; el resto de modulos actua sobre el equipo LOCAL. Ejecute el script en el equipo objetivo para una adquisicion completa.' -f $TargetComputer)
    }

    
    $selfPath = $MyInvocation.PSCommandPath
    if (-not $selfPath) { $selfPath = $PSCommandPath }
    $script:SelfHash = $null
    $script:SnapshotDevice = $null
    $script:SnapshotId = $null
    $script:SnapshotTried = $false
    $script:VolatileEvidence = New-Object System.Collections.ArrayList
    if ($selfPath -and (Test-Path -LiteralPath $selfPath)) {
        $script:SelfHash = Get-EvidenceFileHash -Path $selfPath -Algorithm SHA256
    }

    
    $osInfo = Get-CimOrWmi -ClassName 'Win32_OperatingSystem'
    $meta = New-Object PSObject -Property @{
        AcquisitionId        = $script:AcquisitionId
        CaseId               = $script:CaseId
        Organization         = $Organization
        Examiner             = $Examiner
        TargetComputer       = $TargetComputer
        LocalComputer        = $env:COMPUTERNAME
        ExecutingUser        = ('{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME)
        IsAdministrator      = $script:IsAdmin
        TokenElevated        = $script:Elevation.IsElevated
        MemberOfAdmins       = $script:Elevation.InAdminGroup
        IntegrityLevel       = $script:Elevation.IntegrityLevel
        ScriptVersion        = $script:ScriptVersion
        ScriptSHA256         = $script:SelfHash
        PowerShellVersion    = $PSVersionTable.PSVersion.ToString()
        OSCaption            = if ($osInfo) { $osInfo.Caption } else { $null }
        OSVersion            = if ($osInfo) { $osInfo.Version } else { $null }
        OSBuild              = if ($osInfo) { $osInfo.BuildNumber } else { $null }
        Architecture         = if ($osInfo) { $osInfo.OSArchitecture } else { $null }
        StartLocal           = $script:StartLocal.ToString($script:TsFmt)
        StartUTC             = $script:StartUtc.ToString($script:TsFmt)
        CaseTimeZoneRef      = $TimeZone
        SystemTimeZone       = $(try { [TimeZoneInfo]::Local.Id } catch { $null })
        UTCOffsetMinutes     = $(try { [int][TimeZoneInfo]::Local.GetUtcOffset((Get-Date)).TotalMinutes } catch { $null })
        FilterStartDate      = $StartDate.ToString($script:TsFmt)
        FilterEndDate        = $EndDate.ToString($script:TsFmt)
        OutputVolume         = $(try { (Get-Item $script:OutputPath).PSDrive.Name } catch { $null })
        ReadOnlyMode         = $ReadOnlyMode
        ModulesRequested     = ($Modules -join ',')
        HashAlgorithms       = ($HashAlgorithms -join ',')
        Notes                = 'Adquisicion en vivo: el proceso de adquisicion genera inevitablemente nuevos procesos, eventos 4688/4103/4104 y posibles actualizaciones de LastAccess. Vease Impact_Statement.'
    }
    $metaFile = Join-Path $script:Paths.Meta 'case_metadata.json'
    try {
        [System.IO.File]::WriteAllText($metaFile, ($meta | ConvertTo-Json -Depth 4), (New-Object System.Text.UTF8Encoding($false)))
    } catch {
        $meta | Out-File -LiteralPath $metaFile -Encoding UTF8
    }

    
    $impact = @(
        'DECLARACION DE IMPACTO DE LA ADQUISICION EN VIVO'
        '================================================='
        'La ejecucion de este script produce, de forma inevitable y documentada:'
        ' 1. Creacion de procesos (powershell.exe, cmd.exe y herramientas nativas invocadas).'
        ' 2. Nuevos eventos de seguridad y operacionales (p.ej. 4688 Process Creation,'
        '    4103/4104 PowerShell, 4672/4624 asociados a la sesion del examinador).'
        ' 3. Lecturas de archivos que pueden actualizar el atributo LastAccess si'
        '    NtfsDisableLastAccessUpdate esta deshabilitado en el sistema.'
        ' 4. Escritura de archivos exclusivamente en el soporte de destino (OutputPath).'
        ' 5. Cambios en memoria RAM, caches de disco y tablas del sistema.'
        ' 6. Conexiones de red solo si OutputPath es una ruta remota o TargetComputer difiere.'
        'El script NO borra, NO modifica y NO limpia ninguna informacion del sistema objetivo,'
        'NO cambia politicas ni configuracion, NO habilita auditorias y NO reinicia servicios.'
        'Ninguna adquisicion en vivo puede garantizarse totalmente inalterable; esta declaracion'
        'delimita el impacto conocido conforme a UNE 71506.'
    )
    $impactFile = Join-Path $script:Paths.Meta 'Impact_Statement.txt'
    $impact | Out-File -LiteralPath $impactFile -Encoding UTF8
    Register-Evidence -Path $metaFile   -Category 'Metadata' -SourceDescription 'Metadatos del caso'
    Register-Evidence -Path $impactFile -Category 'Metadata' -SourceDescription 'Declaracion de impacto'
}

function Test-ModuleSelected {
    param([string]$Name)
    return ($Modules -contains 'All' -or $Modules -contains $Name)
}




function Invoke-ModuleSystemInfo {
    if (-not (Test-ModuleSelected 'SystemInfo')) { return }
    Write-ForensicLog -Message '--- MODULO SystemInfo ---'
    Register-Source 'Win32_OperatingSystem / Win32_ComputerSystem / Win32_BIOS / systeminfo'

    $txtDir = $script:Paths.ParsedTXT

    
    $os   = Get-CimOrWmi -ClassName 'Win32_OperatingSystem'
    $cs   = Get-CimOrWmi -ClassName 'Win32_ComputerSystem'
    $bios = Get-CimOrWmi -ClassName 'Win32_BIOS'
    $tz   = Get-CimOrWmi -ClassName 'Win32_TimeZone'

    $lastBoot = $null; $installDate = $null
    if ($os) {
        try {
            if ($os.LastBootUpTime -is [datetime]) { $lastBoot = $os.LastBootUpTime }
            else { $lastBoot = [Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime) }
        } catch { }
        try {
            if ($os.InstallDate -is [datetime]) { $installDate = $os.InstallDate }
            else { $installDate = [Management.ManagementDateTimeConverter]::ToDateTime($os.InstallDate) }
        } catch { }
    }
    $uptime = $null
    if ($lastBoot) { $uptime = ((Get-Date) - $lastBoot).ToString() }

    $sysInfo = New-Object PSObject -Property @{
        ComputerName        = $env:COMPUTERNAME
        Domain              = if ($cs) { $cs.Domain } else { $null }
        PartOfDomain        = if ($cs) { $cs.PartOfDomain } else { $null }
        Manufacturer        = if ($cs) { $cs.Manufacturer } else { $null }
        Model               = if ($cs) { $cs.Model } else { $null }
        BIOSSerialNumber    = if ($bios) { $bios.SerialNumber } else { $null }
        OSCaption           = if ($os) { $os.Caption } else { $null }
        OSVersion           = if ($os) { $os.Version } else { $null }
        OSBuild             = if ($os) { $os.BuildNumber } else { $null }
        OSArchitecture      = if ($os) { $os.OSArchitecture } else { $null }
        OSInstallDateLocal  = if ($installDate) { $installDate.ToString($script:TsFmt) } else { $null }
        LastBootLocal       = if ($lastBoot) { $lastBoot.ToString($script:TsFmt) } else { $null }
        LastBootUTC         = if ($lastBoot) { $lastBoot.ToUniversalTime().ToString($script:TsFmt) } else { $null }
        UptimeAtAcquisition = $uptime
        TimeZoneId          = $(try { [TimeZoneInfo]::Local.Id } catch { if ($tz) { $tz.StandardName } else { $null } })
        UTCOffsetMinutes    = $(try { [int][TimeZoneInfo]::Local.GetUtcOffset((Get-Date)).TotalMinutes } catch { $null })
        NowLocal            = Get-NowLocalString
        NowUTC              = Get-NowUtcString
        SystemLocale        = $(try { (Get-Culture).Name } catch { $null })
        PSVersion           = $PSVersionTable.PSVersion.ToString()
    }
    Export-ObjectData -Data $sysInfo -BaseName '01_system_identification' -Category 'SystemInfo'

    
    Invoke-NativeTool -Executable 'systeminfo.exe' -OutputFile (Join-Path $txtDir 'systeminfo.txt') -Description 'Informacion completa del sistema' | Out-Null
    Register-Evidence -Path (Join-Path $txtDir 'systeminfo.txt') -Category 'SystemInfo' -SourceDescription 'systeminfo.exe'

    
    
    
    
    Register-Source 'w32tm / servicio W32Time (configuracion NTP)'
    $w32Status = 'Desconocido'; $w32Start = 'Desconocido'
    try {
        $svcW32 = Get-Service -Name W32Time -ErrorAction Stop
        $w32Status = [string]$svcW32.Status
        try { $w32Start = [string](Get-CimOrWmi -ClassName 'Win32_Service' -Filter "Name='W32Time'" | Select-Object -First 1 -ExpandProperty StartMode) } catch { }
    } catch { }
    $timeSyncRec = New-Object PSObject -Property @{
        CollectedUTC = Get-NowUtcString
        W32TimeServiceStatus = $w32Status; W32TimeStartMode = $w32Start
        NtpServer = $null; NtpType = $null; LastSyncNote = $null
        Assessment = $null
    }
    
    try {
        $p = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters'
        if (Test-Path $p) {
            $timeSyncRec.NtpServer = (Get-ItemProperty -Path $p -Name NtpServer -ErrorAction SilentlyContinue).NtpServer
            $timeSyncRec.NtpType   = (Get-ItemProperty -Path $p -Name Type -ErrorAction SilentlyContinue).Type
        }
    } catch { }
    if ($w32Status -eq 'Running') {
        Invoke-NativeTool -Executable 'w32tm.exe' -Arguments '/query /status /verbose' -OutputFile (Join-Path $txtDir 'w32tm_status.txt') -Description 'Estado sincronizacion NTP' | Out-Null
        Invoke-NativeTool -Executable 'w32tm.exe' -Arguments '/query /configuration' -OutputFile (Join-Path $txtDir 'w32tm_configuration.txt') -Description 'Configuracion NTP' | Out-Null
        Invoke-NativeTool -Executable 'w32tm.exe' -Arguments '/query /peers' -OutputFile (Join-Path $txtDir 'w32tm_peers.txt') -Description 'Peers NTP' | Out-Null
        foreach ($f in 'w32tm_status.txt','w32tm_configuration.txt','w32tm_peers.txt') {
            Register-Evidence -Path (Join-Path $txtDir $f) -Category 'SystemInfo' -SourceDescription 'w32tm.exe'
        }
        $timeSyncRec.Assessment = 'Servicio Hora de Windows en ejecucion: el reloj puede sincronizarse por NTP (ver w32tm_status.txt para la ultima sincronizacion y el desfase).'
    } else {
        $timeSyncRec.Assessment = ('Servicio Hora de Windows (W32Time) NO en ejecucion (estado: {0}, inicio: {1}). El equipo no sincroniza su reloj por NTP mientras el servicio este parado: la hora del sistema puede tener deriva. No se ha iniciado el servicio para no alterar el sistema investigado. Verificar la exactitud del reloj frente a una fuente externa (ver comparacion de reloj en este informe).' -f $w32Status, $w32Start)
        Write-ForensicLog -Level INFO -Message ('[HECHO] Servicio W32Time no en ejecucion (estado {0}); w32tm /query no aplicable. Configuracion NTP tomada del Registro.' -f $w32Status)
        Register-MissingEvidence -Evidence 'w32tm /query (estado NTP en vivo)' -Reason ('El servicio Hora de Windows (W32Time) esta {0}; w32tm /query requiere el servicio en ejecucion (0x80070426). Se documenta como hecho del sistema; configuracion NTP obtenida del Registro.' -f $w32Status) -Status 'DISABLED'
    }
    
    Invoke-NativeTool -Executable 'w32tm.exe' -Arguments '/tz' -OutputFile (Join-Path $txtDir 'w32tm_tz.txt') -Description 'Zona horaria del sistema' | Out-Null
    if (Test-Path (Join-Path $txtDir 'w32tm_tz.txt')) { Register-Evidence -Path (Join-Path $txtDir 'w32tm_tz.txt') -Category 'SystemInfo' -SourceDescription 'w32tm.exe /tz' }
    Export-ObjectData -Data @($timeSyncRec) -BaseName '01b_time_sync_status' -Category 'SystemInfo'

    
    Register-Source 'auditpol (politica de auditoria avanzada)'
    if ($script:IsAdmin) {
        Invoke-NativeTool -Executable 'auditpol.exe' -Arguments '/get /category:* /r' -OutputFile (Join-Path $txtDir 'auditpol_full.csv') -Description 'Politica de auditoria avanzada (CSV)' | Out-Null
        Register-Evidence -Path (Join-Path $txtDir 'auditpol_full.csv') -Category 'SystemInfo' -SourceDescription 'auditpol.exe /get /category:* /r'
    } else {
        Register-MissingEvidence -Evidence 'auditpol /get /category:*' -Reason 'Requiere privilegios de administrador'
    }

    
    Register-Source 'wevtutil el / Get-WinEvent -ListLog (inventario de canales)'
    $logInventory = New-Object System.Collections.ArrayList
    if (Test-CommandAvailable 'Get-WinEvent') {
        try {
            Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | ForEach-Object {
                $log = $_
                $oldest = $null; $oldestL = $null; $newest = $null; $newestL = $null
                
                $estado = 'OPERATIVO'
                if (-not $log.IsEnabled) { $estado = 'DISABLED' }
                elseif ($null -eq $log.RecordCount) { $estado = 'INACCESIBLE' }
                elseif ($log.RecordCount -eq 0) { $estado = 'EMPTY' }
                if ($log.RecordCount -gt 0) {
                    
                    try {
                        $evO = Get-WinEvent -LogName $log.LogName -MaxEvents 1 -Oldest -ErrorAction Stop
                        if ($evO) { $oldest = $evO.TimeCreated.ToUniversalTime().ToString($script:TsFmt); $oldestL = (ConvertTo-MadridTimeString $evO.TimeCreated) }
                    } catch {
                        
                        try {
                            $evO2 = Get-WinEvent -FilterHashtable @{ LogName = $log.LogName } -MaxEvents 1 -Oldest -ErrorAction Stop
                            if ($evO2) { $oldest = $evO2.TimeCreated.ToUniversalTime().ToString($script:TsFmt); $oldestL = (ConvertTo-MadridTimeString $evO2.TimeCreated) }
                        } catch { $estado = 'ACCESS_DENIED_OR_LOCKED' }
                    }
                    
                    try {
                        $evN = Get-WinEvent -LogName $log.LogName -MaxEvents 1 -ErrorAction Stop
                        if ($evN) { $newest = $evN.TimeCreated.ToUniversalTime().ToString($script:TsFmt); $newestL = (ConvertTo-MadridTimeString $evN.TimeCreated) }
                    } catch { }
                }
                [void]$logInventory.Add((New-Object PSObject -Property @{
                    LogName          = $log.LogName
                    Estado           = $estado
                    IsEnabled        = $log.IsEnabled
                    RecordCount      = $log.RecordCount
                    OldestEventUTC   = $oldest
                    OldestEventLocal = $oldestL
                    NewestEventUTC   = $newest
                    NewestEventLocal = $newestL
                    FileSizeBytes    = $log.FileSize
                    MaxSizeBytes     = $log.MaximumSizeInBytes
                    LogMode          = $log.LogMode
                    LogFilePath      = $log.LogFilePath
                }))
            }
        } catch {
            Write-ForensicLog -Level ERROR -Message ('Inventario de logs fallo: {0}' -f $_.Exception.Message)
        }
    }
    if ($logInventory.Count -gt 0) {
        Export-ObjectData -Data $logInventory -BaseName '02_eventlog_inventory' -Category 'SystemInfo'
    } else {
        Invoke-NativeTool -Executable 'wevtutil.exe' -Arguments 'el' -OutputFile (Join-Path $txtDir 'wevtutil_channels.txt') -Description 'Listado de canales (fallback)' | Out-Null
        Register-Evidence -Path (Join-Path $txtDir 'wevtutil_channels.txt') -Category 'SystemInfo' -SourceDescription 'wevtutil el'
    }

    
    Register-Source 'SecurityCenter2 / Win32_Service (AV, EDR, Sysmon)'
    $secProducts = Get-CimOrWmi -ClassName 'AntiVirusProduct' -Namespace 'root\SecurityCenter2'
    if ($secProducts) {
        $avList = @($secProducts | ForEach-Object {
            New-Object PSObject -Property @{
                DisplayName = $_.displayName; ProductState = $_.productState
                PathToSignedProductExe = $_.pathToSignedProductExe; TimestampUTC = Get-NowUtcString
            }
        })
        Export-ObjectData -Data $avList -BaseName '03_security_products' -Category 'SecurityTools'
    } else {
        Register-MissingEvidence -Evidence 'root\SecurityCenter2 AntiVirusProduct' -Reason 'Namespace no disponible (habitual en Windows Server) o sin productos registrados' -Status 'NOT_APPLICABLE'
    }
    
    $edrServiceNames = @('Sysmon','Sysmon64','SysmonDrv','CSFalconService','CylanceSvc','SentinelAgent',
                         'xagt','CarbonBlack','CbDefense','mfemms','SepMasterService','WinDefend','MsMpSvc',
                         'ekrn','klnagent','TmListen','HealthService','elastic-agent','osqueryd')
    $svcAll = Get-CimOrWmi -ClassName 'Win32_Service'
    if ($svcAll) {
        $secSvc = @($svcAll | Where-Object { $edrServiceNames -contains $_.Name } | ForEach-Object {
            New-Object PSObject -Property @{
                ServiceName = $_.Name; DisplayName = $_.DisplayName; State = $_.State
                StartMode = $_.StartMode; PathName = $_.PathName; TimestampUTC = Get-NowUtcString
            }
        })
        if ($secSvc.Count -gt 0) { Export-ObjectData -Data $secSvc -BaseName '04_security_services_detected' -Category 'SecurityTools' }
    }
    Write-ForensicLog -Message 'Modulo SystemInfo completado.'
}




function Invoke-ModuleUsers {
    if (-not (Test-ModuleSelected 'Users') -or -not $IncludeUserArtifacts) { return }
    Write-ForensicLog -Message '--- MODULO Users ---'
    Register-Source 'Win32_UserAccount / Win32_Group / Win32_GroupUser / Win32_UserProfile'

    
    $users = Get-CimOrWmi -ClassName 'Win32_UserAccount' -Filter "LocalAccount='True'"
    if ($users) {
        $uList = @($users | ForEach-Object {
            New-Object PSObject -Property @{
                Name = $_.Name; Domain = $_.Domain; SID = $_.SID; Disabled = $_.Disabled
                Lockout = $_.Lockout; PasswordRequired = $_.PasswordRequired
                PasswordChangeable = $_.PasswordChangeable; Description = $_.Description
                TimestampUTC = Get-NowUtcString
            }
        })
        Export-ObjectData -Data $uList -BaseName '10_local_users' -Category 'Users'
    }

    
    
    
    $privSids = @('S-1-5-32-544','S-1-5-32-551','S-1-5-32-555','S-1-5-32-580')
    $groupMembers = New-Object System.Collections.ArrayList
    foreach ($sid in $privSids) {
        $grp = Get-CimOrWmi -ClassName 'Win32_Group' -Filter ("SID='{0}'" -f $sid)
        if (-not $grp) { continue }
        $grpName = @($grp)[0].Name
        
        try {
            $q = ('ASSOCIATORS OF {{Win32_Group.Domain=''{0}'',Name=''{1}''}} WHERE AssocClass=Win32_GroupUser' -f @($grp)[0].Domain, $grpName)
            $members = $null
            if (Test-CommandAvailable 'Get-CimInstance') {
                $members = Get-CimInstance -Query $q -ErrorAction SilentlyContinue
            } elseif (Test-CommandAvailable 'Get-WmiObject') {
                $members = Get-WmiObject -Query $q -ErrorAction SilentlyContinue
            }
            foreach ($m in @($members)) {
                if ($null -eq $m) { continue }
                [void]$groupMembers.Add((New-Object PSObject -Property @{
                    GroupSID = $sid; GroupName = $grpName
                    MemberDomain = $m.Domain; MemberName = $m.Name
                    MemberSID = $m.SID; MemberClass = $m.PSObject.TypeNames[0]
                    TimestampUTC = Get-NowUtcString
                }))
            }
        } catch {
            Write-ForensicLog -Level DEBUG -Message ('Miembros de grupo {0} no enumerables: {1}' -f $sid, $_.Exception.Message)
        }
    }
    if ($groupMembers.Count -gt 0) {
        Export-ObjectData -Data $groupMembers -BaseName '11_privileged_group_members' -Category 'Users'
    } else {
        Register-MissingEvidence -Evidence 'Miembros de grupos privilegiados' -Reason 'Consulta WMI Win32_GroupUser sin resultados o fallida'
    }

    
    $profiles = Get-CimOrWmi -ClassName 'Win32_UserProfile'
    if ($profiles) {
        $pList = @($profiles | ForEach-Object {
            $lastUse = $null
            try {
                if ($_.LastUseTime -is [datetime]) { $lastUse = $_.LastUseTime }
                elseif ($_.LastUseTime) { $lastUse = [Management.ManagementDateTimeConverter]::ToDateTime($_.LastUseTime) }
            } catch { }
            New-Object PSObject -Property @{
                SID = $_.SID; LocalPath = $_.LocalPath; Special = $_.Special; Loaded = $_.Loaded
                LastUseLocal = if ($lastUse) { $lastUse.ToString($script:TsFmt) } else { $null }
                LastUseUTC   = if ($lastUse) { $lastUse.ToUniversalTime().ToString($script:TsFmt) } else { $null }
                NoteLastUse  = 'LastUseTime en Win10+ puede actualizarse por procesos del sistema; valor orientativo, correlar con 4624'
                TimestampUTC = Get-NowUtcString
            }
        })
        Export-ObjectData -Data $pList -BaseName '12_user_profiles' -Category 'Users'
    }

    
    Invoke-NativeTool -Executable 'whoami.exe' -Arguments '/all' -OutputFile (Join-Path $script:Paths.ParsedTXT 'whoami_examiner.txt') -Description 'Contexto de seguridad del ejecutor' | Out-Null
    Register-Evidence -Path (Join-Path $script:Paths.ParsedTXT 'whoami_examiner.txt') -Category 'Users' -SourceDescription 'whoami /all (examinador)'
    Write-ForensicLog -Message 'Modulo Users completado.'
}







$script:EventChannels = @(
    @{ Channel='Security';                                                        Tag='Security' }
    @{ Channel='System';                                                          Tag='System' }
    @{ Channel='Application';                                                     Tag='Application' }
    @{ Channel='Microsoft-Windows-PowerShell/Operational';                        Tag='PowerShell_Operational' }
    @{ Channel='Windows PowerShell';                                              Tag='PowerShell_Classic' }
    @{ Channel='Microsoft-Windows-TaskScheduler/Operational';                     Tag='TaskScheduler' }
    @{ Channel='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; Tag='TS_LocalSessionManager' }
    @{ Channel='Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; Tag='TS_RemoteConnectionManager' }
    @{ Channel='Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational';   Tag='RdpCoreTS' }
    @{ Channel='Microsoft-Windows-TerminalServices-RDPClient/Operational';        Tag='RDPClient_Outbound' }
    @{ Channel='Microsoft-Windows-WinRM/Operational';                             Tag='WinRM' }
    @{ Channel='Microsoft-Windows-WMI-Activity/Operational';                      Tag='WMI_Activity' }
    @{ Channel='Microsoft-Windows-SmbServer/Security';                            Tag='SMB_Server_Security' }
    @{ Channel='Microsoft-Windows-SmbServer/Operational';                         Tag='SMB_Server_Operational' }
    @{ Channel='Microsoft-Windows-SmbClient/Security';                            Tag='SMB_Client' }
    @{ Channel='Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'; Tag='Firewall' }
    @{ Channel='Microsoft-Windows-Windows Defender/Operational';                  Tag='Defender' }
    @{ Channel='Microsoft-Windows-AppLocker/EXE and DLL';                         Tag='AppLocker_EXE' }
    @{ Channel='Microsoft-Windows-Sysmon/Operational';                            Tag='Sysmon' }
    @{ Channel='OpenSSH/Operational';                                             Tag='OpenSSH' }
    @{ Channel='Microsoft-Windows-Bits-Client/Operational';                       Tag='BITS' }
    @{ Channel='Microsoft-Windows-GroupPolicy/Operational';                       Tag='GroupPolicy' }
    @{ Channel='Microsoft-Windows-User Profile Service/Operational';              Tag='UserProfileService' }
    @{ Channel='Microsoft-Windows-Ntfs/Operational';                              Tag='NTFS' }
    @{ Channel='Microsoft-Windows-Kernel-PnP/Configuration';                      Tag='PnP_USB' }
    @{ Channel='Microsoft-Windows-DriverFrameworks-UserMode/Operational';         Tag='USB_UserMode' }
    @{ Channel='Microsoft-Windows-NetworkProfile/Operational';                    Tag='NetworkProfile' }
    @{ Channel='Microsoft-Windows-RemoteAccess-RemoteAccessServer';               Tag='RemoteAccess_VPN' }
)


$script:SecurityIdsOfInterest = @(
    1102,                                   
    4608,4616,4696,                         
    4624,4625,4634,4647,4648,4649,          
    4672,4673,4674,                         
    4688,4689,                              
    4697,                                   
    4698,4699,4700,4701,4702,               
    4719,4817,4902,4904,4905,4906,4907,4912,
    4720,4722,4723,4724,4725,4726,          
    4728,4729,4732,4733,4746,4747,4751,4752,4756,4757,4761,4762, 
    4738,4740,4767,4781,                    
    4768,4769,4770,4771,4776,4778,4779,     
    4798,4799,                              
    4657,4658,4660,4663,4670,4690,          
    5140,5142,5144,5145,                    
    5136,5141,                              
    5152,5154,5156,5158,5157,               
    4964                                    
)

function Export-RawEventLogs {
    
    $sUtc = $StartDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.000Z')
    $eUtc = $EndDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.999Z')
    $xpath = "*[System[TimeCreated[@SystemTime>='$sUtc' and @SystemTime<='$eUtc']]]"
    $remoteArg = ''
    if ($TargetComputer -ne $env:COMPUTERNAME) { $remoteArg = ('/r:{0} ' -f $TargetComputer) }

    foreach ($def in $script:EventChannels) {
        $channel = $def.Channel; $tag = $def.Tag
        Register-Source ('Canal de eventos: {0}' -f $channel)
        
        $exists = $false
        try {
            if (Test-CommandAvailable 'Get-WinEvent') {
                $l = Get-WinEvent -ListLog $channel -ErrorAction Stop
                $exists = ($null -ne $l)
            } else { $exists = $true }  
        } catch { $exists = $false }
        if (-not $exists) {
            Register-MissingEvidence -Evidence ('Canal {0}' -f $channel) -Reason 'Canal no presente en este sistema (version de Windows o componente no instalado)' -Status 'NOT_INSTALLED'
            continue
        }
        $outFile = Join-Path $script:Paths.RawEvt ($tag + '.evtx')
        $ok = Invoke-NativeTool -Executable 'wevtutil.exe' `
            -Arguments ('epl "{0}" "{1}" "/q:{2}" {3}/ow:true' -f $channel, $outFile, $xpath, $remoteArg) `
            -Description ('Exportacion EVTX nativa de {0} filtrada por fechas' -f $channel)
        if ($ok -and (Test-Path -LiteralPath $outFile)) {
            Register-Evidence -Path $outFile -Category 'EventLogs' -SourceDescription $channel `
                -Notes ('EVTX nativo filtrado {0} a {1} UTC' -f $sUtc, $eUtc)
        } elseif (-not $script:IsAdmin -and $channel -eq 'Security') {
            Register-MissingEvidence -Evidence 'Security.evtx' -Reason 'Requiere privilegios de administrador' -Status 'ACCESS_DENIED'
        } else {
            Register-MissingEvidence -Evidence ('EVTX {0}' -f $channel) -Reason 'wevtutil epl devolvio error (vease log de comandos)'
        }
    }
}

function Get-LogonFailureReason {
    



    param([string]$Code)
    if (-not $Code) { return $null }
    $c = $Code.ToLowerInvariant().Trim()
    if ($c -notmatch '^0x') { $c = '0x' + $c }
    $map = @{
        '0xc0000064' = 'La cuenta de usuario no existe'
        '0xc000006a' = 'Contrasena incorrecta'
        '0xc000006d' = 'Nombre de usuario incorrecto o credenciales invalidas'
        '0xc000006e' = 'Restriccion de cuenta (horario, caducidad, etc.)'
        '0xc000006f' = 'Inicio fuera del horario permitido'
        '0xc0000070' = 'Estacion de trabajo no autorizada'
        '0xc0000071' = 'Contrasena caducada'
        '0xc0000072' = 'Cuenta deshabilitada'
        '0xc000005e' = 'No hay servidores de inicio de sesion disponibles'
        '0xc0000133' = 'Desfase de reloj entre equipos (Kerberos)'
        '0xc0000193' = 'Cuenta caducada'
        '0xc0000224' = 'Se requiere cambio de contrasena'
        '0xc0000234' = 'Cuenta bloqueada por intentos fallidos'
        '0xc00002ee' = 'Error durante el inicio de sesion (causa no especificada)'
        '0xc0000413' = 'Autenticacion rechazada por politica de firewall/autenticacion'
        '0x0'        = 'Correcto'
    }
    $desc = $map[$c]
    if ($desc) { return ('{0} ({1})' -f $desc, $c) }
    return ('Codigo no catalogado ({0})' -f $c)
}

function Convert-EventToNormalizedRecord {
    





    param($Event, [string]$ChannelTag)
    $data = @{}
    try {
        $xml = [xml]$Event.ToXml()
        if ($xml.Event.EventData -and $xml.Event.EventData.Data) {
            foreach ($d in @($xml.Event.EventData.Data)) {
                if ($d -is [string]) { continue }
                $n = $d.Name
                if ($n) { $data[$n] = $d.'#text' }
            }
        }
        
        
        
        if ($xml.Event.UserData) {
            foreach ($container in @($xml.Event.UserData.ChildNodes)) {
                if ($null -eq $container -or -not $container.ChildNodes) { continue }
                foreach ($c in @($container.ChildNodes)) {
                    if ($null -eq $c -or -not $c.Name -or $c.Name -eq '#text') { continue }
                    if (-not $data.ContainsKey($c.Name)) { $data[$c.Name] = $c.InnerText }
                }
            }
        }
    } catch { }
    $tc = $Event.TimeCreated
    $get = { param($k) if ($data.ContainsKey($k)) { $data[$k] } else { $null } }
    $userName = & $get 'TargetUserName'; if (-not $userName) { $userName = & $get 'SubjectUserName' }
    if (-not $userName) { $userName = & $get 'User' }        
    if (-not $userName) { $userName = & $get 'Param1' }      
    $userSid  = & $get 'TargetUserSid';  if (-not $userSid)  { $userSid  = & $get 'SubjectUserSid' }
    $notesPairs = New-Object System.Collections.ArrayList
    foreach ($k in $data.Keys) { [void]$notesPairs.Add(('{0}={1}' -f $k, $data[$k])) }

    New-Object PSObject -Property @{
        TimestampLocal   = if ($tc) { ConvertTo-MadridTimeString $tc } else { $null }
        TimestampUTC     = if ($tc) { $tc.ToUniversalTime().ToString($script:TsFmt) } else { $null }
        TimeZoneOffset   = $(try { [TimeZoneInfo]::Local.GetUtcOffset($tc).ToString() } catch { $null })
        Source           = 'EventLog'
        Channel          = $Event.LogName
        Provider         = $Event.ProviderName
        EventId          = $Event.Id
        RecordId         = $Event.RecordId
        Computer         = $Event.MachineName
        User             = $userName
        UserSID          = $userSid
        SourceIP         = $(if ((& $get 'IpAddress') -and (& $get 'IpAddress') -ne '-') { & $get 'IpAddress' } elseif (& $get 'Address') { & $get 'Address' } elseif (& $get 'Param3') { & $get 'Param3' } else { $null })
        DestinationIP    = $null
        SourcePort       = & $get 'IpPort'
        DestinationPort  = $null
        Protocol         = & $get 'AuthenticationPackageName'
        LogonType        = & $get 'LogonType'
        SessionId        = $(if (& $get 'SessionID') { & $get 'SessionID' } else { & $get 'SessionId' })
        WorkstationName  = & $get 'WorkstationName'
        ProcessName      = if ($data.ContainsKey('NewProcessName')) { $data['NewProcessName'] } elseif ($data.ContainsKey('ProcessName')) { $data['ProcessName'] } else { $null }
        ProcessId        = if ($data.ContainsKey('NewProcessId')) { $data['NewProcessId'] } elseif ($data.ContainsKey('ProcessId')) { $data['ProcessId'] } else { $null }
        ParentProcessId  = & $get 'ParentProcessId'
        ParentProcessName = & $get 'ParentProcessName'
        CommandLine      = & $get 'CommandLine'
        LogonProcessName = & $get 'LogonProcessName'
        TokenElevationType = & $get 'TokenElevationType'
        SubjectUserName  = & $get 'SubjectUserName'
        SubjectDomainName = & $get 'SubjectDomainName'
        SubjectLogonId   = & $get 'SubjectLogonId'
        TargetLogonId    = & $get 'TargetLogonId'
        StatusCode       = & $get 'Status'
        SubStatusCode    = & $get 'SubStatus'
        FailureReason    = $(if ($Event.Id -eq 4625) { $ss = (& $get 'SubStatus'); $st = (& $get 'Status'); Get-LogonFailureReason $(if ($ss -and $ss -ne '0x0') { $ss } else { $st }) } else { $null })
        FilePath         = & $get 'ObjectName'
        OldFilePath      = $null
        NewFilePath      = $null
        Action           = $null
        HashSHA256       = $null
        EvidenceFile     = $ChannelTag
        ConfidenceLevel  = 'Registro directo del sistema'
        Notes            = ($notesPairs -join '; ')
    }
}

function Export-ParsedEvents {
    



    if (-not (Test-CommandAvailable 'Get-WinEvent')) {
        Register-MissingEvidence -Evidence 'Eventos normalizados' -Reason 'Get-WinEvent no disponible; solo se conservan EVTX nativos'
        return
    }
    $batchSize = 5000   
    $jobs = @(
        @{ Channel='Security'; Ids=$script:SecurityIdsOfInterest; Base='20_security_events' }
        @{ Channel='System'; Ids=@(104,1074,6005,6006,6008,7034,7035,7036,7040,7045,1,12,13); Base='21_system_events' }
        @{ Channel='Microsoft-Windows-PowerShell/Operational'; Ids=@(4103,4104,4105,4106,53504); Base='22_powershell_events' }
        @{ Channel='Windows PowerShell'; Ids=@(400,403,600,800); Base='22b_powershell_classic' }
        @{ Channel='Microsoft-Windows-TaskScheduler/Operational'; Ids=@(100,102,106,110,129,140,141,200,201); Base='23_taskscheduler_events' }
        @{ Channel='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; Ids=@(21,22,23,24,25,39,40); Base='24_rdp_lsm_events' }
        @{ Channel='Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; Ids=@(1149); Base='25_rdp_rcm_events' }
        @{ Channel='Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational'; Ids=@(98,131,140); Base='26_rdpcorets_events' }
        @{ Channel='Microsoft-Windows-TerminalServices-RDPClient/Operational'; Ids=@(1024,1102); Base='27_rdp_outbound_events' }
        @{ Channel='Microsoft-Windows-WinRM/Operational'; Ids=@(6,91,168,169); Base='28_winrm_events' }
        @{ Channel='Microsoft-Windows-WMI-Activity/Operational'; Ids=@(5857,5858,5859,5860,5861); Base='29_wmi_events' }
        @{ Channel='Microsoft-Windows-Windows Defender/Operational'; Ids=@(1116,1117,1118,1119,5001,5004,5007,5010,5012); Base='30_defender_events' }
        @{ Channel='Microsoft-Windows-Bits-Client/Operational'; Ids=@(59,60,61); Base='31_bits_events' }
        @{ Channel='Microsoft-Windows-Sysmon/Operational'; Ids=@(1,3,5,7,8,10,11,13,17,18,22,23,25,26); Base='32_sysmon_events' }
        @{ Channel='OpenSSH/Operational'; Ids=$null; Base='33_openssh_events' }
        @{ Channel='Microsoft-Windows-SmbServer/Security'; Ids=$null; Base='34_smb_server_events' }
    )
    foreach ($job in $jobs) {
        $channel = $job.Channel
        $csvOut  = Join-Path $script:Paths.ParsedCSV ($job.Base + '.csv')
        
        
        
        $idChunks = @()
        if ($job.Ids) {
            $idsAll = @($job.Ids)
            if ($idsAll.Count -le 22) { $idChunks = @(, $idsAll) }
            else {
                for ($i = 0; $i -lt $idsAll.Count; $i += 22) {
                    $endIdx = [math]::Min($i + 21, $idsAll.Count - 1)
                    $idChunks += , @($idsAll[$i..$endIdx])
                }
            }
        } else { $idChunks = @($null) }

        $count = 0
        $buffer = New-Object System.Collections.ArrayList
        $accessDenied = $false; $otherErr = $null
        foreach ($ids in $idChunks) {
            $filter = @{ LogName = $channel; StartTime = $StartDate; EndTime = $EndDate }
            if ($ids) { $filter['Id'] = $ids }
            try {
                Get-WinEvent -FilterHashtable $filter -ErrorAction Stop | ForEach-Object {
                    $rec = Convert-EventToNormalizedRecord -Event $_ -ChannelTag $job.Base
                    [void]$buffer.Add($rec)
                    $count++
                    if ($buffer.Count -ge $batchSize) {
                        $buffer | Export-Csv -LiteralPath $csvOut -NoTypeInformation -Encoding UTF8 -Append
                        $buffer.Clear()
                    }
                }
            } catch {
                $msg = $_.Exception.Message
                if ($msg -match 'No events were found|NoMatchingEventsFound') { }
                elseif ($msg -match 'Attempted to perform an unauthorized|Acceso denegado|Access is denied') { $accessDenied = $true }
                else { $otherErr = $msg }
            }
        }
        if ($buffer.Count -gt 0) {
            $buffer | Export-Csv -LiteralPath $csvOut -NoTypeInformation -Encoding UTF8 -Append
            $buffer.Clear()
        }
        if ($count -gt 0) {
            Register-Evidence -Path $csvOut -Category 'EventLogs' -SourceDescription $channel `
                -Notes ('{0} eventos normalizados (streaming, bloques de {1})' -f $count, $batchSize)
            Write-ForensicLog -Message ('{0}: {1} eventos normalizados' -f $channel, $count)
        } elseif ($accessDenied) {
            Register-MissingEvidence -Evidence ('Eventos de {0}' -f $channel) -Reason 'Acceso denegado (se requieren privilegios de administrador)'
        } elseif ($otherErr) {
            $errStatus = 'ACQUISITION_FAILED'
            if ($otherErr -match '(?i)no se encontraron eventos|no events were found|no coincid|no events match') { $errStatus = 'EMPTY' }
            elseif ($otherErr -match '(?i)no hay un registro de eventos|there is no event log|no existe|not found|could not be found|no se encuentra') { $errStatus = 'NOT_INSTALLED' }
            elseif ($otherErr -match '(?i)acceso denegado|access is denied|access denied') { $errStatus = 'ACCESS_DENIED' }
            $reasonTxt = $(switch ($errStatus) {
                'EMPTY'         { 'Canal existente sin eventos coincidentes en el rango (sin actividad, auditoria no habilitada o registros rotados)' }
                'NOT_INSTALLED' { 'Canal no presente en este sistema (componente/rol no instalado)' }
                'ACCESS_DENIED' { 'Acceso denegado al canal (privilegios insuficientes)' }
                default         { ('Error al consultar el canal: {0}' -f $otherErr) }
            })
            Register-MissingEvidence -Evidence ('Eventos de {0}' -f $channel) -Reason $reasonTxt -Status $errStatus
        } else {
            Register-MissingEvidence -Evidence ('Eventos de {0} en el periodo' -f $channel) -Reason 'Sin eventos coincidentes: sin actividad, auditoria no habilitada o registros rotados/sobrescritos'
        }
    }
}

function Invoke-ModuleEventLogs {
    if (-not (Test-ModuleSelected 'EventLogs') -or -not $IncludeEventLogs) { return }
    Write-ForensicLog -Message '--- MODULO EventLogs ---'
    if ($ExportRawEvidence)    { Export-RawEventLogs }
    if ($ExportParsedEvidence) { Export-ParsedEvents }
    Write-ForensicLog -Message 'Modulo EventLogs completado.'
}




function Invoke-ModuleRegistry {
    if (-not (Test-ModuleSelected 'Registry')) { return }
    Write-ForensicLog -Message '--- MODULO Registry ---'
    Register-Source 'reg save / reg export (hives y claves)'
    $regDir = $script:Paths.RawReg

    
    
    $cfgDir = (Get-WinEnvPath SystemRoot).TrimEnd('\') + '\System32\config'
    $hives = @(
        @{ Key='HKLM\SAM';      File='SAM.hiv';      Cfg=($cfgDir + '\SAM') }
        @{ Key='HKLM\SECURITY'; File='SECURITY.hiv'; Cfg=($cfgDir + '\SECURITY') }
        @{ Key='HKLM\SYSTEM';   File='SYSTEM.hiv';   Cfg=($cfgDir + '\SYSTEM') }
        @{ Key='HKLM\SOFTWARE'; File='SOFTWARE.hiv'; Cfg=($cfgDir + '\SOFTWARE') }
    )
    foreach ($h in $hives) {
        Save-SystemHive -Key $h.Key -Dest (Join-Path $regDir $h.File) -ConfigFile $h.Cfg | Out-Null
    }

    
    $profiles = Get-CimOrWmi -ClassName 'Win32_UserProfile'
    foreach ($p in @($profiles)) {
        if ($null -eq $p -or $p.Special) { continue }
        $lp = $p.LocalPath
        if (-not $lp -or -not (Test-Path -LiteralPath $lp)) { continue }
        $sidSafe = ($p.SID -replace '[^A-Za-z0-9-]','_')
        $ntuser  = Join-Path $lp 'NTUSER.DAT'
        $usrcls  = Join-Path $lp 'AppData\Local\Microsoft\Windows\UsrClass.dat'
        if ($p.Loaded -and $script:IsAdmin) {
            
            $dest = Join-Path $regDir ('NTUSER_{0}.hiv' -f $sidSafe)
            $ok = Invoke-NativeTool -Executable 'reg.exe' -Arguments ('save "HKU\{0}" "{1}" /y' -f $p.SID, $dest) -Description ('reg save NTUSER de {0}' -f $p.SID)
            if ($ok -and (Test-Path -LiteralPath $dest)) {
                Register-Evidence -Path $dest -Category 'Registry' -SourceDescription $ntuser -Notes 'Perfil cargado: reg save HKU\SID'
            }
            $destC = Join-Path $regDir ('UsrClass_{0}.hiv' -f $sidSafe)
            $okC = Invoke-NativeTool -Executable 'reg.exe' -Arguments ('save "HKU\{0}_Classes" "{1}" /y' -f $p.SID, $destC) -Description ('reg save UsrClass de {0}' -f $p.SID)
            if ($okC -and (Test-Path -LiteralPath $destC)) {
                Register-Evidence -Path $destC -Category 'Registry' -SourceDescription $usrcls -Notes 'Perfil cargado: reg save HKU\SID_Classes (ShellBags)'
            }
        } else {
            Copy-EvidenceFile -SourcePath $ntuser -DestinationPath (Join-Path $regDir ('NTUSER_{0}.DAT' -f $sidSafe)) -Category 'Registry' -Notes 'Perfil no cargado: copia directa' | Out-Null
            Copy-EvidenceFile -SourcePath $usrcls -DestinationPath (Join-Path $regDir ('UsrClass_{0}.dat' -f $sidSafe)) -Category 'Registry' -Notes 'Perfil no cargado: copia directa (ShellBags)' | Out-Null
        }
    }

    
    $keys = @(
        @{ K='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run';                        F='HKLM_Run.reg' }
        @{ K='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce';                    F='HKLM_RunOnce.reg' }
        @{ K='HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run';            F='HKLM_Run_Wow64.reg' }
        @{ K='HKLM\SYSTEM\CurrentControlSet\Services';                                    F='Services.reg' }
        @{ K='HKLM\SYSTEM\MountedDevices';                                                F='MountedDevices.reg' }
        @{ K='HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR';                                F='USBSTOR.reg' }
        @{ K='HKLM\SYSTEM\CurrentControlSet\Enum\USB';                                    F='USB.reg' }
        @{ K='HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList';             F='ProfileList.reg' }
        @{ K='HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon';                F='Winlogon.reg' }
        @{ K='HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server';                     F='TerminalServer.reg' }
        @{ K='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies';                   F='Policies_HKLM.reg' }
        @{ K='HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions';                       F='Defender_Exclusions.reg' }
        @{ K='HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'; F='IFEO.reg' }
        @{ K='HKLM\SYSTEM\CurrentControlSet\Control\Session Manager';                     F='SessionManager.reg' }
        @{ K='HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache';      F='TaskCache.reg' }
    )
    foreach ($k in $keys) {
        $dest = Join-Path $regDir $k.F
        $ok = Invoke-NativeTool -Executable 'reg.exe' -Arguments ('export "{0}" "{1}" /y' -f $k.K, $dest) -Description ('reg export {0}' -f $k.K)
        if ($ok -and (Test-Path -LiteralPath $dest)) {
            Register-Evidence -Path $dest -Category 'Registry' -SourceDescription $k.K
        } else {
            Register-MissingEvidence -Evidence $k.K -Reason 'Clave inexistente o acceso denegado'
        }
    }

    
    $userKeys = @(
        @{ K='Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs';                 F='RecentDocs' }
        @{ K='Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist';                 F='UserAssist' }
        @{ K='Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths';                 F='TypedPaths' }
        @{ K='Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32';                   F='ComDlg32_MRU' }
        @{ K='Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU';                     F='RunMRU' }
        @{ K='Software\Microsoft\Terminal Server Client';                                     F='RDP_Client_MRU' }
        @{ K='Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2';               F='MountPoints2' }
        @{ K='Software\Microsoft\Internet Explorer\TypedURLs';                                F='TypedURLs' }
        @{ K='Software\Microsoft\Windows\CurrentVersion\Run';                                 F='User_Run' }
    )
    $hkuUsers = @()
    try { $hkuUsers = & reg.exe query HKU 2>$null | Where-Object { $_ -match 'S-1-5-21-' -and $_ -notmatch '_Classes' } } catch { }
    foreach ($line in $hkuUsers) {
        $sid = ($line -replace '.*\\','').Trim()
        $sidSafe = ($sid -replace '[^A-Za-z0-9-]','_')
        foreach ($uk in $userKeys) {
            $dest = Join-Path $regDir ('User_{0}_{1}.reg' -f $sidSafe, $uk.F)
            Invoke-NativeTool -Executable 'reg.exe' -Arguments ('export "HKU\{0}\{1}" "{2}" /y' -f $sid, $uk.K, $dest) -Description ('reg export usuario {0}: {1}' -f $sid, $uk.F) | Out-Null
            if (Test-Path -LiteralPath $dest) { Register-Evidence -Path $dest -Category 'Registry' -SourceDescription ('HKU\{0}\{1}' -f $sid, $uk.K) }
        }
    }
    Write-ForensicLog -Message 'Modulo Registry completado.'
}




function Invoke-ModuleFileSystem {
    if (-not (Test-ModuleSelected 'FileSystem') -or -not $IncludeFileSystemArtifacts) { return }
    Write-ForensicLog -Message '--- MODULO FileSystem ---'
    $fsDir = $script:Paths.RawFS
    $sys   = Get-WinEnvPath SystemRoot

    
    Register-Source 'Prefetch (C:\Windows\Prefetch)'
    $pfDir = Join-Path $sys 'Prefetch'
    if (Test-Path -LiteralPath $pfDir) {
        $pfFiles = @(Get-ChildItem -LiteralPath $pfDir -Filter '*.pf' -Force -ErrorAction SilentlyContinue)
        if ($pfFiles.Count -gt 0) {
            $pfDest = Join-Path $fsDir 'Prefetch'
            New-Item -Path $pfDest -ItemType Directory -Force | Out-Null
            foreach ($f in $pfFiles) {
                Copy-EvidenceFile -SourcePath $f.FullName -DestinationPath (Join-Path $pfDest $f.Name) -Category 'FileSystem' -Notes 'Prefetch (evidencia de ejecucion)' | Out-Null
            }
            
            $pfMeta = @($pfFiles | ForEach-Object {
                New-Object PSObject -Property @{
                    FileName = $_.Name; SizeBytes = $_.Length
                    CreatedUTC  = $_.CreationTimeUtc.ToString($script:TsFmt)
                    ModifiedUTC = $_.LastWriteTimeUtc.ToString($script:TsFmt)
                    AccessedUTC = $_.LastAccessTimeUtc.ToString($script:TsFmt)
                    Note = 'LastWrite ~ ultima ejecucion; parseo de contenido requiere PECmd u equivalente'
                }
            })
            Export-ObjectData -Data $pfMeta -BaseName '40_prefetch_metadata' -Category 'FileSystem'
        } else {
            Register-MissingEvidence -Evidence 'Prefetch' -Reason 'Carpeta vacia, deshabilitado (habitual en Server/SSD por politica) o sin permisos de lectura'
        }
    } else {
        Register-MissingEvidence -Evidence 'Prefetch' -Reason 'Carpeta inexistente (deshabilitado en este sistema)'
    }

    
    Register-Source 'Amcache.hve / RecentFileCache.bcf'
    Copy-EvidenceFile -SourcePath (Join-Path $sys 'appcompat\Programs\Amcache.hve') -DestinationPath (Join-Path $fsDir 'Amcache.hve') -Category 'FileSystem' -Notes 'Amcache (parseo con AmcacheParser u offline)' | Out-Null
    Copy-EvidenceFile -SourcePath (Join-Path $sys 'AppCompat\Programs\RecentFileCache.bcf') -DestinationPath (Join-Path $fsDir 'RecentFileCache.bcf') -Category 'FileSystem' -Notes 'Solo Win7/2008R2-2012; puede no existir' | Out-Null
    
    Write-ForensicLog -Message 'Shimcache (AppCompatCache) incluido en SYSTEM.hiv; requiere parseo offline (AppCompatCacheParser).'

    
    Register-Source 'SRUM (SRUDB.dat)'
    Copy-EvidenceFile -SourcePath (Join-Path $sys 'System32\sru\SRUDB.dat') -DestinationPath (Join-Path $fsDir 'SRUDB.dat') -Category 'FileSystem' -Notes 'SRUM: consumo de red/CPU por app y usuario; parseo offline (srum-dump)' | Out-Null

    
    Register-Source 'LNK / JumpLists / ConsoleHost_history / $Recycle.Bin'
    $profiles = Get-CimOrWmi -ClassName 'Win32_UserProfile'
    foreach ($p in @($profiles)) {
        if ($null -eq $p -or $p.Special) { continue }
        $lp = $p.LocalPath
        if (-not $lp -or -not (Test-Path -LiteralPath $lp)) { continue }
        $sidSafe = ($p.SID -replace '[^A-Za-z0-9-]','_')
        $userDest = Join-Path $fsDir ('Profile_{0}' -f $sidSafe)
        $artifacts = @(
            @{ Src='AppData\Roaming\Microsoft\Windows\Recent';                          Dst='Recent';            Note='LNK y JumpLists (Automatic/CustomDestinations)' }
            @{ Src='AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine';           Dst='PSReadLine';        Note='ConsoleHost_history.txt: historial PowerShell' }
            @{ Src='AppData\Roaming\Microsoft\Office\Recent';                           Dst='OfficeRecent';      Note='Documentos recientes Office' }
            @{ Src='AppData\Local\Microsoft\Windows\WebCache';                          Dst='WebCache';          Note='WebCacheV01.dat: historial IE/Edge legacy y shell' }
        )
        foreach ($a in $artifacts) {
            $srcPath = Join-Path $lp $a.Src
            if (Test-Path -LiteralPath $srcPath) {
                $files = @(Get-ChildItem -LiteralPath $srcPath -Recurse -Force -File -ErrorAction SilentlyContinue)
                $nF = $files.Count; $iF = 0; $okF = 0; $t0 = Get-Date
                if ($nF -gt 0) { Write-ForensicLog -Message ('FileSystem: copiando {0} ({1} archivo(s)) del perfil {2}...' -f $a.Dst, $nF, $p.SID) }
                foreach ($f in $files) {
                    $iF++
                    $rel = $f.FullName.Substring($srcPath.Length).TrimStart('\')
                    if (Copy-EvidenceFile -SourcePath $f.FullName -DestinationPath (Join-Path (Join-Path $userDest $a.Dst) $rel) -Category 'FileSystem' -Notes $a.Note) { $okF++ }
                    
                    if (($iF % 200) -eq 0 -or ((Get-Date) - $t0).TotalSeconds -ge 20) {
                        Write-Host ('   ... {0}: {1}/{2} archivos ({3} copiados)' -f $a.Dst, $iF, $nF, $okF) -ForegroundColor DarkGray
                        $t0 = Get-Date
                    }
                }
                if ($nF -gt 0) { Write-ForensicLog -Message ('FileSystem: {0} -> {1}/{2} archivos copiados.' -f $a.Dst, $okF, $nF) }
            }
        }
    }

    
    $recycleMeta = New-Object System.Collections.ArrayList
    foreach ($drive in @(Get-CimOrWmi -ClassName 'Win32_LogicalDisk' -Filter "DriveType=3")) {
        if ($null -eq $drive) { continue }
        $rb = Join-Path $drive.DeviceID '$Recycle.Bin'
        if (-not (Test-Path -LiteralPath $rb)) { continue }
        
        $items = @(Get-ChildItem -LiteralPath $rb -Recurse -Force -ErrorAction SilentlyContinue | Select-Object -First 20000)
        if ($items.Count -ge 20000) { Write-ForensicLog -Level WARN -Message ('Papelera {0}: mas de 20000 elementos; se documentan los primeros 20000 (resto en imagen offline).' -f $rb) }
        foreach ($it in $items) {
            [void]$recycleMeta.Add((New-Object PSObject -Property @{
                Path = $it.FullName; IsContainer = $it.PSIsContainer
                SizeBytes = if ($it.PSIsContainer) { $null } else { $it.Length }
                CreatedUTC  = $it.CreationTimeUtc.ToString($script:TsFmt)
                ModifiedUTC = $it.LastWriteTimeUtc.ToString($script:TsFmt)
                Note = 'Archivos $I contienen ruta original y fecha de borrado (parseo offline); $R es el contenido'
            }))
            
            if (-not $it.PSIsContainer -and $it.Name -like '$I*') {
                $rel = ($it.FullName -replace '[:\\]','_')
                Copy-EvidenceFile -SourcePath $it.FullName -DestinationPath (Join-Path (Join-Path $fsDir 'RecycleBin_I') $rel) -Category 'FileSystem' -Notes 'Indice $I de papelera' | Out-Null
            }
        }
    }
    if ($recycleMeta.Count -gt 0) { Export-ObjectData -Data $recycleMeta -BaseName '41_recyclebin_metadata' -Category 'FileSystem' }
    else { Register-MissingEvidence -Evidence 'Papelera de reciclaje' -Reason 'Vacia, purgada (posible antiforensia) o sin acceso' }

    
    
    
    
    
    Register-Source 'Recorrido MACB de perfiles de usuario y rutas temporales'
    $scanRoots = New-Object System.Collections.ArrayList
    foreach ($p in @($profiles)) { if ($p -and -not $p.Special -and $p.LocalPath) { [void]$scanRoots.Add($p.LocalPath) } }
    [void]$scanRoots.Add((Join-Path $sys 'Temp'))
    $macbCsv = Join-Path $script:Paths.ParsedCSV '42_file_timeline_macb.csv'
    $macbCount = 0; $macbSeen = 0; $macbPartial = New-Object System.Collections.ArrayList
    $macbBuf = New-Object System.Collections.ArrayList
    $macbHeaderWritten = (Test-Path -LiteralPath $macbCsv)
    $flushMacb = {
        if ($macbBuf.Count -gt 0) {
            $macbBuf | Export-Csv -LiteralPath $macbCsv -NoTypeInformation -Encoding UTF8 -Append
            $macbBuf.Clear()
        }
    }
    
    
    $macbSkipDirs = @(
        '\\AppData\\Local\\Microsoft\\Windows\\INetCache', '\\AppData\\Local\\Microsoft\\Windows\\WebCache',
        '\\AppData\\Local\\Google\\Chrome\\User Data\\[^\\]+\\(Cache|Code Cache|GPUCache|Service Worker|DawnCache|ShaderCache)',
        '\\AppData\\Local\\Microsoft\\Edge\\User Data\\[^\\]+\\(Cache|Code Cache|GPUCache|Service Worker|DawnCache|ShaderCache)',
        '\\AppData\\Local\\BraveSoftware\\[^\\]+\\User Data\\[^\\]+\\(Cache|Code Cache|GPUCache|Service Worker)',
        '\\AppData\\Local\\Mozilla\\Firefox\\Profiles\\[^\\]+\\cache2',
        '\\AppData\\Local\\Packages\\[^\\]+\\(AC|LocalCache|TempState)',
        '\\AppData\\Local\\Microsoft\\OneDrive\\(logs|setup)', '\\AppData\\Local\\Temp\\[^\\]*(chocolatey|pip|npm|nuget)',
        '\\node_modules\\', '\\\.git\\objects\\', '\\AppData\\Local\\Microsoft\\VisualStudio\\', '\\AppData\\Local\\JetBrains\\',
        '\\AppData\\Local\\Docker\\', '\\AppData\\Local\\Steam\\', '\\AppData\\Local\\Microsoft\\Teams\\(Cache|Code Cache|GPUCache|Service Worker)',
        '\\AppData\\Local\\Spotify\\', '\\AppData\\Local\\Adobe\\', '\\AppData\\Local\\NVIDIA\\', '\\AppData\\Local\\Comms\\'
    )
    $macbSkipRe = ('(?i)(' + ($macbSkipDirs -join '|') + ')')
    $incS = $script:IncidentStartUtc; $incE = $script:IncidentEndUtc
    if (-not $incS) { $incS = $(if ($IncidentStart -ne [datetime]::MinValue) { $IncidentStart.ToUniversalTime() } else { $EndDate.AddDays(-7).ToUniversalTime() }) }
    if (-not $incE) { $incE = $(if ($IncidentEnd -ne [datetime]::MinValue) { $IncidentEnd.ToUniversalTime() } else { $EndDate.ToUniversalTime() }) }
    foreach ($root in $scanRoots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $rootCount = 0; $rootSeen = 0; $cut = $false; $lastProg = Get-Date
        
        $stack = New-Object System.Collections.Stack
        $stack.Push($root)
        while ($stack.Count -gt 0) {
            $dir = $stack.Pop()
            if ($MaxScanSecondsPerRoot -gt 0 -and $sw.Elapsed.TotalSeconds -gt $MaxScanSecondsPerRoot) { $cut = $true; break }
            
            if (((Get-Date) - $lastProg).TotalSeconds -ge 20) { Write-Host ('   ... MACB {0}: {1} archivos vistos, {2} en rango, {3} s' -f $root, $rootSeen, $rootCount, [int]$sw.Elapsed.TotalSeconds) -ForegroundColor DarkGray; $lastProg = Get-Date }
            $subs = $null
            try { $subs = [System.IO.Directory]::GetDirectories($dir) } catch { $subs = $null }
            if ($subs) {
                foreach ($sd in $subs) {
                    if ($sd -match $macbSkipRe) { continue }
                    
                    try { $da = [System.IO.File]::GetAttributes($sd); if (([int]$da -band 0x400) -ne 0) { continue } } catch { continue }
                    $stack.Push($sd)
                }
            }
            $files = $null
            try { $files = [System.IO.Directory]::GetFiles($dir) } catch { $files = $null }
            if (-not $files) { continue }
            foreach ($fp in $files) {
                $rootSeen++
                try {
                    $fi = New-Object System.IO.FileInfo($fp)
                    $cT = $fi.CreationTimeUtc; $mT = $fi.LastWriteTimeUtc
                    $inRange = ($cT -ge $StartDate.ToUniversalTime() -and $cT -le $EndDate.ToUniversalTime()) -or ($mT -ge $StartDate.ToUniversalTime() -and $mT -le $EndDate.ToUniversalTime())
                    if (-not $inRange) { continue }
                    $inIncident = ($cT -ge $incS -and $cT -le $incE) -or ($mT -ge $incS -and $mT -le $incE)
                    $owner = $null
                    if ($inIncident) { try { $owner = [System.IO.File]::GetAccessControl($fp).GetOwner([System.Security.Principal.NTAccount]).Value } catch { } }
                    [void]$macbBuf.Add((New-Object PSObject -Property @{
                        FilePath      = $fp
                        Extension     = $fi.Extension
                        SizeBytes     = $fi.Length
                        Owner         = $owner
                        InIncidentWindow = $(if ($inIncident) { 'Si' } else { 'No' })
                        CreatedLocal  = (ConvertTo-MadridTimeString $cT)
                        CreatedUTC    = $cT.ToString($script:TsFmt)
                        ModifiedLocal = (ConvertTo-MadridTimeString $mT)
                        ModifiedUTC   = $mT.ToString($script:TsFmt)
                        AccessedUTC   = $fi.LastAccessTimeUtc.ToString($script:TsFmt)
                        Attributes    = $fi.Attributes.ToString()
                        Note          = 'MACB desde API en vivo; MFT/$LogFile/USN requieren imagen offline. LastAccess fiable solo si NtfsDisableLastAccessUpdate=0. Propietario resuelto solo para archivos del periodo del incidente.'
                    }))
                    $rootCount++
                    if ($macbBuf.Count -ge 5000) { & $flushMacb }
                } catch { }
            }
        }
        & $flushMacb
        $sw.Stop()
        $macbCount += $rootCount; $macbSeen += $rootSeen
        if ($cut) {
            [void]$macbPartial.Add($root)
            Write-ForensicLog -Level WARN -Message ('Recorrido MACB de {0} CORTADO por presupuesto de tiempo ({1} s): {2} archivos vistos, {3} en rango. Se documenta como parcial.' -f $root, $MaxScanSecondsPerRoot, $rootSeen, $rootCount)
        } else {
            Write-ForensicLog -Message ('Recorrido MACB de {0}: {1} archivos vistos, {2} en rango, {3} s.' -f $root, $rootSeen, $rootCount, [int]$sw.Elapsed.TotalSeconds)
        }
    }
    if ($macbCount -gt 0) {
        Register-Evidence -Path $macbCsv -Category 'FileSystem' -SourceDescription 'Listado MACB perfiles+temp' -Notes ('{0} archivos en rango de {1} vistos{2}' -f $macbCount, $macbSeen, $(if ($macbPartial.Count -gt 0) { '; PARCIAL (corte por tiempo) en: ' + ($macbPartial -join ', ') } else { '' }))
    }
    if ($macbPartial.Count -gt 0) {
        Register-MissingEvidence -Evidence 'Recorrido MACB completo de perfiles' -Reason ('Recorrido cortado por presupuesto de tiempo en: {0}. El listado es PARCIAL; la timeline completa del sistema de archivos ($MFT/USN) se obtiene de la imagen offline o de KAPE.' -f ($macbPartial -join ', ')) -Status 'REQUIRES_OFFLINE_ACQUISITION'
    }

    
    Invoke-NativeTool -Executable 'fsutil.exe' -Arguments 'behavior query DisableLastAccess' -OutputFile (Join-Path $script:Paths.ParsedTXT 'ntfs_lastaccess_policy.txt') -Description 'Politica LastAccess (fiabilidad del atributo A)' | Out-Null
    Register-Evidence -Path (Join-Path $script:Paths.ParsedTXT 'ntfs_lastaccess_policy.txt') -Category 'FileSystem' -SourceDescription 'fsutil behavior query DisableLastAccess'
    if ($script:IsAdmin) {
        Invoke-NativeTool -Executable 'fsutil.exe' -Arguments ('usn queryjournal {0}' -f (Get-WinEnvPath SystemDrive)) -OutputFile (Join-Path $script:Paths.ParsedTXT 'usn_journal_status.txt') -Description 'Estado del USN Journal (solo consulta)' | Out-Null
        Register-Evidence -Path (Join-Path $script:Paths.ParsedTXT 'usn_journal_status.txt') -Category 'FileSystem' -SourceDescription 'fsutil usn queryjournal'
        Invoke-NativeTool -Executable 'vssadmin.exe' -Arguments 'list shadows' -OutputFile (Join-Path $script:Paths.ParsedTXT 'vss_shadows.txt') -Description 'Listado de instantaneas VSS (solo lectura)' | Out-Null
        Invoke-NativeTool -Executable 'vssadmin.exe' -Arguments 'list shadowstorage' -OutputFile (Join-Path $script:Paths.ParsedTXT 'vss_storage.txt') -Description 'Almacenamiento VSS' | Out-Null
        Register-Evidence -Path (Join-Path $script:Paths.ParsedTXT 'vss_shadows.txt') -Category 'FileSystem' -SourceDescription 'vssadmin list shadows'
        Register-Evidence -Path (Join-Path $script:Paths.ParsedTXT 'vss_storage.txt') -Category 'FileSystem' -SourceDescription 'vssadmin list shadowstorage'
    } else {
        Register-MissingEvidence -Evidence 'USN Journal / VSS' -Reason 'Consulta requiere administrador'
    }
    Write-ForensicLog -Message 'Modulo FileSystem completado. MFT, $LogFile y contenido de USN requieren imagen forense o herramienta de acceso raw.'
}




function Invoke-ModuleRemoteAccess {
    if (-not (Test-ModuleSelected 'RemoteAccess') -or -not $IncludeRemoteAccessArtifacts) { return }
    Write-ForensicLog -Message '--- MODULO RemoteAccess ---'
    $raDir = $script:Paths.RawRemote

    
    Register-Source 'Terminal Server / WinRM configuracion'
    Invoke-NativeTool -Executable 'reg.exe' -Arguments 'query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections' -OutputFile (Join-Path $script:Paths.ParsedTXT 'rdp_enabled_state.txt') -Description 'Estado RDP (fDenyTSConnections)' | Out-Null
    Register-Evidence -Path (Join-Path $script:Paths.ParsedTXT 'rdp_enabled_state.txt') -Category 'RemoteAccess' -SourceDescription 'fDenyTSConnections'
    if (Test-CommandAvailable 'winrm.cmd') {
        Invoke-NativeTool -Executable 'winrm.cmd' -Arguments 'get winrm/config' -OutputFile (Join-Path $script:Paths.ParsedTXT 'winrm_config.txt') -Description 'Configuracion WinRM' | Out-Null
        Register-Evidence -Path (Join-Path $script:Paths.ParsedTXT 'winrm_config.txt') -Category 'RemoteAccess' -SourceDescription 'winrm get winrm/config'
    }

    
    Register-Source 'OpenSSH (ProgramData\ssh)'
    $sshDir = Join-Path (Get-WinEnvPath ProgramData) 'ssh'
    if (Test-Path -LiteralPath $sshDir) {
        foreach ($f in @(Get-ChildItem -LiteralPath $sshDir -Force -File -ErrorAction SilentlyContinue)) {
            if ($f.Extension -in '.log','.txt','' -or $f.Name -match 'sshd_config|administrators_authorized_keys') {
                Copy-EvidenceFile -SourcePath $f.FullName -DestinationPath (Join-Path (Join-Path $raDir 'OpenSSH') $f.Name) -Category 'RemoteAccess' -Notes 'OpenSSH config/logs' | Out-Null
            }
        }
    }
    
    $profiles = Get-CimOrWmi -ClassName 'Win32_UserProfile'
    foreach ($p in @($profiles)) {
        if ($null -eq $p -or $p.Special -or -not $p.LocalPath) { continue }
        $ak = Join-Path $p.LocalPath '.ssh'
        if (Test-Path -LiteralPath $ak) {
            $sidSafe = ($p.SID -replace '[^A-Za-z0-9-]','_')
            foreach ($f in @(Get-ChildItem -LiteralPath $ak -Force -File -ErrorAction SilentlyContinue)) {
                
                if ($f.Name -match '^(authorized_keys|known_hosts|config)$') {
                    Copy-EvidenceFile -SourcePath $f.FullName -DestinationPath (Join-Path (Join-Path $raDir ('OpenSSH_User_' + $sidSafe)) $f.Name) -Category 'RemoteAccess' -Notes 'SSH usuario (sin claves privadas)' | Out-Null
                }
            }
        }
    }

    
    
    
    Register-Source 'Herramientas de control remoto (TeamViewer, AnyDesk, RustDesk, Supremo, Splashtop, VNC, CRD, LogMeIn)'
    $pf   = Get-WinEnvPath ProgramFiles
    $pf86 = Get-WinEnvPath ProgramFilesX86
    $pd   = Get-WinEnvPath ProgramData
    $remoteTools = @(
        @{ Name='TeamViewer';          Paths=@("$pf\TeamViewer","$pf86\TeamViewer");                                  Logs=@("$pf\TeamViewer\*.log","$pf86\TeamViewer\*.log","$pd\TeamViewer\*.log") }
        @{ Name='AnyDesk';             Paths=@("$pf\AnyDesk","$pf86\AnyDesk","$pd\AnyDesk");                          Logs=@("$pd\AnyDesk\*.trace","$pd\AnyDesk\connection_trace.txt") }
        @{ Name='RustDesk';            Paths=@("$pf\RustDesk","$pd\RustDesk");                                        Logs=@("$pd\RustDesk\log\*.log") }
        @{ Name='Supremo';             Paths=@("$pf86\Supremo","$pd\SupremoRemoteDesktop");                           Logs=@("$pd\SupremoRemoteDesktop\Log\*.log","$pd\SupremoRemoteDesktop\*.log") }
        @{ Name='Splashtop';           Paths=@("$pf86\Splashtop","$pf\Splashtop");                                    Logs=@("$pd\Splashtop\Temp\log\*.txt","$pf86\Splashtop\Splashtop Remote\Server\log\*.txt") }
        @{ Name='LogMeIn';             Paths=@("$pf86\LogMeIn","$pf\LogMeIn");                                        Logs=@("$pd\LogMeIn\*.log") }
        @{ Name='ChromeRemoteDesktop'; Paths=@("$pf86\Google\Chrome Remote Desktop","$pf\Google\Chrome Remote Desktop"); Logs=@("$pd\Google\Chrome Remote Desktop\*.log") }
        @{ Name='UltraVNC';            Paths=@("$pf\uvnc bvba","$pf86\uvnc bvba","$pf\UltraVNC");                     Logs=@("$pf\UltraVNC\*.log","$pf86\uvnc bvba\UltraVnc\*.log") }
        @{ Name='TightVNC';            Paths=@("$pf\TightVNC","$pf86\TightVNC");                                      Logs=@() }
        @{ Name='RealVNC';             Paths=@("$pf\RealVNC","$pf86\RealVNC");                                        Logs=@("$pd\RealVNC-Service\vncserver.log") }
    )
    $detected = New-Object System.Collections.ArrayList
    foreach ($tool in $remoteTools) {
        $found = $false; $foundPath = $null
        foreach ($tp in $tool.Paths) {
            if ($tp -and (Test-Path -LiteralPath $tp)) { $found = $true; $foundPath = $tp; break }
        }
        
        if (-not $found) {
            foreach ($p in @($profiles)) {
                if ($null -eq $p -or $p.Special -or -not $p.LocalPath) { continue }
                $cand = Join-Path $p.LocalPath ('AppData\Roaming\' + $tool.Name)
                if (Test-Path -LiteralPath $cand) { $found = $true; $foundPath = $cand; break }
            }
        }
        [void]$detected.Add((New-Object PSObject -Property @{
            Tool = $tool.Name; Detected = $found; Path = $foundPath; TimestampUTC = Get-NowUtcString
        }))
        if ($found) {
            Write-ForensicLog -Message ('Herramienta de control remoto detectada: {0} en {1}' -f $tool.Name, $foundPath)
            foreach ($pattern in $tool.Logs) {
                if (-not $pattern) { continue }
                foreach ($lf in @(Get-ChildItem -Path $pattern -Force -ErrorAction SilentlyContinue)) {
                    Copy-EvidenceFileFrozen -SourcePath $lf.FullName -DestinationPath (Join-Path (Join-Path $raDir $tool.Name) $lf.Name) -Category 'RemoteAccess' -Notes ('Log de {0}: contiene IP remota, ID y sesiones' -f $tool.Name) | Out-Null
                }
            }
            
            foreach ($p in @($profiles)) {
                if ($null -eq $p -or $p.Special -or -not $p.LocalPath) { continue }
                $sidSafe = ($p.SID -replace '[^A-Za-z0-9-]','_')
                $userLogDirs = @(
                    (Join-Path $p.LocalPath ('AppData\Roaming\' + $tool.Name)),
                    (Join-Path $p.LocalPath ('AppData\Local\'   + $tool.Name))
                )
                foreach ($uld in $userLogDirs) {
                    if (-not (Test-Path -LiteralPath $uld)) { continue }
                    foreach ($lf in @(Get-ChildItem -LiteralPath $uld -Recurse -Force -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in '.log','.trace','.txt','.conf','.toml' })) {
                        Copy-EvidenceFileFrozen -SourcePath $lf.FullName -DestinationPath (Join-Path (Join-Path (Join-Path $raDir $tool.Name) ('User_' + $sidSafe)) $lf.Name) -Category 'RemoteAccess' -Notes ('Log usuario de {0}' -f $tool.Name) | Out-Null
                    }
                }
            }
        }
    }
    Export-ObjectData -Data $detected -BaseName '50_remote_tools_detection' -Category 'RemoteAccess'

    
    foreach ($p in @($profiles)) {
        if ($null -eq $p -or $p.Special -or -not $p.LocalPath) { continue }
        $sidSafe = ($p.SID -replace '[^A-Za-z0-9-]','_')
        $rdpCache = Join-Path $p.LocalPath 'AppData\Local\Microsoft\Terminal Server Client\Cache'
        if (Test-Path -LiteralPath $rdpCache) {
            foreach ($f in @(Get-ChildItem -LiteralPath $rdpCache -Force -File -ErrorAction SilentlyContinue)) {
                Copy-EvidenceFile -SourcePath $f.FullName -DestinationPath (Join-Path (Join-Path $raDir ('RDP_BitmapCache_' + $sidSafe)) $f.Name) -Category 'RemoteAccess' -Notes 'Cache de bitmaps RDP saliente (parseo con bmc-tools)' | Out-Null
            }
        }
        $defRdp = Join-Path $p.LocalPath 'Documents\Default.rdp'
        Copy-EvidenceFile -SourcePath $defRdp -DestinationPath (Join-Path $raDir ('Default_rdp_' + $sidSafe + '.rdp')) -Category 'RemoteAccess' -Notes 'Ultimo destino RDP del usuario' | Out-Null
    }
    
    $rsRecs = New-Object System.Collections.ArrayList
    $rsChannels = @(
        @{ Ch='Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; Ids=@(1149) },
        @{ Ch='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; Ids=@(21,22,23,24,25,39,40) }
    )
    foreach ($rc in $rsChannels) {
        $evs = @()
        try { $evs = @(Get-WinEvent -FilterHashtable @{ LogName=$rc.Ch; Id=$rc.Ids; StartTime=$StartDate; EndTime=$EndDate } -ErrorAction Stop) }
        catch { $evs = @() }
        foreach ($e in $evs) {
            $d = Get-EventDataHash $e
            $id = [int]$e.Id; $user = $null; $ip = $null; $sess = $null; $type = $null
            if ($id -eq 1149) {
                $user = $d['Param1']; $dom = $d['Param2']; $ip = $d['Param3']
                if ($dom -and $user) { $user = ('{0}\{1}' -f $dom, $user) }
                $type = 'Autenticacion RDP entrante (1149)'
            } else {
                $user = $d['User']; $ip = $d['Address']; $sess = $d['SessionID']
                $type = switch ($id) { 21 {'Inicio de sesion RDP (21)'} 22 {'Shell RDP iniciado (22)'} 23 {'Cierre de sesion RDP (23)'} 24 {'Desconexion RDP (24)'} 25 {'Reconexion RDP (25)'} 39 {'Sesion desconectada por otra sesion (39)'} 40 {'Desconexion (40) motivo=' + $d['Reason']} default { ('LSM ' + $id) } }
            }
            if (-not $ip -and -not $user -and -not $sess) { continue }
            [void]$rsRecs.Add((New-Object PSObject -Property @{
                TimestampUTC = $e.TimeCreated.ToUniversalTime().ToString($script:TsFmt)
                TimestampLocal = (ConvertTo-MadridTimeString $e.TimeCreated)
                WhenUtc = $e.TimeCreated.ToUniversalTime()
                EventId = $id; SessionType = $type; User = $user; SourceIP = $ip; SessionId = $sess
                Channel = (Split-Path $rc.Ch -Leaf)
            }))
        }
    }
    if ($rsRecs.Count -gt 0) {
        Export-ObjectData -Data @($rsRecs | Sort-Object TimestampUTC | Select-Object * -ExcludeProperty WhenUtc) -BaseName '26_remote_sessions' -Category 'RemoteAccess'
        Write-ForensicLog -Message ('RemoteAccess: {0} sesiones remotas consolidadas (usuario/IP/tipo).' -f $rsRecs.Count)

        
        
        
        
        
        $withSid = @($rsRecs | Where-Object { $_.SessionId } | Sort-Object WhenUtc)
        $orphan1149 = @($rsRecs | Where-Object { -not $_.SessionId -and $_.EventId -eq 1149 } | Sort-Object WhenUtc)
        $bySession = @{}
        foreach ($r in $withSid) {
            $sid = [string]$r.SessionId
            if (-not $bySession.ContainsKey($sid)) { $bySession[$sid] = New-Object System.Collections.ArrayList }
            [void]$bySession[$sid].Add($r)
        }
        $segments = New-Object System.Collections.ArrayList
        foreach ($sid in $bySession.Keys) {
            $evs = @($bySession[$sid] | Sort-Object WhenUtc)
            $cur = New-Object System.Collections.ArrayList
            $closed = $false; $lastWhen = $null
            foreach ($e in $evs) {
                $isStart = ($e.EventId -in @(21,1149))
                $gapBig = ($lastWhen -and (($e.WhenUtc - $lastWhen).TotalHours -gt 12))
                if ($cur.Count -gt 0 -and (($isStart -and $closed) -or $gapBig)) {
                    [void]$segments.Add(@{ Sid=$sid; Evs=@($cur) }); $cur = New-Object System.Collections.ArrayList; $closed = $false
                }
                [void]$cur.Add($e)
                if ($e.EventId -eq 23) { $closed = $true }
                $lastWhen = $e.WhenUtc
            }
            if ($cur.Count -gt 0) { [void]$segments.Add(@{ Sid=$sid; Evs=@($cur) }) }
        }
        
        foreach ($o in $orphan1149) {
            $target = $null
            foreach ($sg in $segments) {
                $first = ($sg.Evs | Sort-Object WhenUtc | Select-Object -First 1)
                $delta = ($first.WhenUtc - $o.WhenUtc).TotalSeconds
                if ($delta -ge -5 -and $delta -le 120) { $target = $sg; break }
            }
            if ($target) { $target.Evs = @($target.Evs) + @($o) } else { [void]$segments.Add(@{ Sid='(sin id)'; Evs=@($o) }) }
        }
        $sessionRecs = New-Object System.Collections.ArrayList
        foreach ($sg in $segments) {
            $sid = $sg.Sid
            $evs = @($sg.Evs | Sort-Object WhenUtc)
            $connect = ($evs | Where-Object { $_.EventId -in @(1149,21,25) } | Select-Object -First 1)
            $shell   = ($evs | Where-Object { $_.EventId -eq 22 } | Select-Object -First 1)
            $end     = ($evs | Where-Object { $_.EventId -in @(23,24,40) } | Select-Object -Last 1)
            $userS = (@($evs | ForEach-Object { $_.User } | Where-Object { $_ } | Select-Object -Unique) -join ', ')
            $ipS   = (@($evs | ForEach-Object { $_.SourceIP } | Where-Object { $_ } | Select-Object -Unique) -join ', ')
            $iniUtc = ($evs | Select-Object -First 1).TimestampUTC
            $iniLoc = ($evs | Select-Object -First 1).TimestampLocal
            $durMin = $null
            $c = ($evs | Select-Object -First 1).WhenUtc; $f = ($evs | Select-Object -Last 1).WhenUtc
            if ($c -and $f -and $f -gt $c) { $durMin = [int]([math]::Round(($f - $c).TotalMinutes)) }
            
            $durNota = $(if ($end) { '' } else { ' (sin cierre registrado)' })
            [void]$sessionRecs.Add((New-Object PSObject -Property @{
                SessionId = $sid; Usuario = $userS; IpOrigen = $ipS
                InicioUTC = $iniUtc; InicioLocal = $iniLoc
                Conexion = $(if ($connect) { $connect.SessionType } else { '' })
                ShellIniciado = $(if ($shell) { $shell.TimestampUTC } else { '' })
                Cierre = $(if ($end) { $end.SessionType + ' @ ' + $end.TimestampUTC } else { 'Sin cierre registrado' })
                DuracionMin = $(if ($null -ne $durMin) { [string]$durMin + $durNota } else { $null }); NumEventos = $evs.Count
            }))
        }
        if ($sessionRecs.Count -gt 0) {
            Export-ObjectData -Data @($sessionRecs | Sort-Object InicioUTC) -BaseName '29_rdp_session_timeline' -Category 'RemoteAccess'
            Write-ForensicLog -Message ('RemoteAccess: {0} sesion(es) RDP reconstruidas (Origen->Usuario->Conexion->Cierre).' -f $sessionRecs.Count)
        }
    } else {
        Register-MissingEvidence -Evidence 'Sesiones RDP entrantes (1149/21-25)' -Reason 'Sin eventos en los canales de Terminal Services en el periodo (sin accesos RDP entrantes, o canal sin registros)' -Status 'EMPTY'
    }
    Write-ForensicLog -Message 'Modulo RemoteAccess completado.'
}




function Invoke-ModuleNetwork {
    if (-not (Test-ModuleSelected 'Network') -or -not $IncludeNetworkArtifacts) { return }
    Write-ForensicLog -Message '--- MODULO Network ---'
    $txt = $script:Paths.ParsedTXT
    Register-Source 'ipconfig / route / arp / netstat / netsh / net share'

    $cmds = @(
        @{ E='ipconfig.exe'; A='/all';                                  F='net_ipconfig_all.txt';      D='Interfaces, IP, DNS, gateway' }
        @{ E='ipconfig.exe'; A='/displaydns';                           F='net_dns_cache.txt';         D='Cache DNS (volatil: dominios resueltos recientemente)' }
        @{ E='route.exe';    A='print';                                 F='net_routes.txt';            D='Tabla de rutas' }
        @{ E='arp.exe';      A='-a';                                    F='net_arp.txt';               D='Tabla ARP (equipos vecinos recientes)' }
        @{ E='netstat.exe';  A='-anob';                                 F='net_netstat_anob.txt';      D='Conexiones activas con proceso (requiere admin para -b)' }
        @{ E='netstat.exe';  A='-ano';                                  F='net_netstat_ano.txt';       D='Conexiones activas con PID (fallback sin admin)' }
        @{ E='netsh.exe';    A='advfirewall show allprofiles';          F='net_firewall_profiles.txt'; D='Estado del firewall por perfil' }
        @{ E='netsh.exe';    A='advfirewall firewall show rule name=all verbose'; F='net_firewall_rules.txt'; D='Reglas de firewall (buscar aperturas anomalas)' }
        @{ E='netsh.exe';    A='winhttp show proxy';                    F='net_winhttp_proxy.txt';     D='Proxy WinHTTP (posibles tuneles)' }
        @{ E='netsh.exe';    A='interface portproxy show all';          F='net_portproxy.txt';         D='Port forwarding nativo (tecnica de tunel/pivot)' }
        @{ E='net.exe';      A='share';                                 F='net_shares.txt';            D='Recursos compartidos' }
        @{ E='net.exe';      A='use';                                   F='net_use.txt';               D='Conexiones a recursos remotos del ejecutor' }
        @{ E='net.exe';      A='session';                               F='net_sessions.txt';          D='Sesiones SMB entrantes (admin)' }
        @{ E='nbtstat.exe';  A='-c';                                    F='net_nbtstat_cache.txt';     D='Cache NetBIOS' }
    )
    foreach ($c in $cmds) {
        Invoke-NativeTool -Executable $c.E -Arguments $c.A -OutputFile (Join-Path $txt $c.F) -Description $c.D | Out-Null
        if (Test-Path -LiteralPath (Join-Path $txt $c.F)) {
            Register-Evidence -Path (Join-Path $txt $c.F) -Category 'Network' -SourceDescription ('{0} {1}' -f $c.E, $c.A)
        }
    }

    
    if (Test-CommandAvailable 'Get-NetTCPConnection') {
        $procMap = @{}
        try { foreach ($pp in @(Get-Process -ErrorAction SilentlyContinue)) { if ($pp -and -not $procMap.ContainsKey([int]$pp.Id)) { $procMap[[int]$pp.Id] = $pp } } } catch { }
        try {
            $conns = @(Get-NetTCPConnection -ErrorAction Stop | ForEach-Object {
                $opid = $_.OwningProcess; $pname = $null; $ppath = $null
                if ($opid -ne $null -and $procMap.ContainsKey([int]$opid)) { $po = $procMap[[int]$opid]; $pname = $po.ProcessName; try { $ppath = $po.Path } catch { } }
                New-Object PSObject -Property @{
                    LocalEndpoint = ('{0}:{1}' -f $_.LocalAddress, $_.LocalPort)
                    RemoteEndpoint = ('{0}:{1}' -f $_.RemoteAddress, $_.RemotePort)
                    State = $_.State.ToString(); OwningProcess = $opid
                    ProcessName = $pname; ProcessPath = $ppath
                    LocalAddress = $_.LocalAddress; LocalPort = $_.LocalPort
                    RemoteAddress = $_.RemoteAddress; RemotePort = $_.RemotePort
                    CreationTimeLocal = if ($_.CreationTime) { $_.CreationTime.ToString($script:TsFmt) } else { $null }
                    TimestampUTC = Get-NowUtcString
                }
            })
            Export-ObjectData -Data $conns -BaseName '51_tcp_connections' -Category 'Network'
        } catch { Write-ForensicLog -Level DEBUG -Message ('Get-NetTCPConnection fallo: {0}' -f $_.Exception.Message) }
    } else {
        
        try {
            $procMap2 = @{}
            try { foreach ($pp in @(Get-Process -ErrorAction SilentlyContinue)) { if ($pp -and -not $procMap2.ContainsKey([int]$pp.Id)) { $procMap2[[int]$pp.Id] = $pp } } } catch { }
            $netstatOut = & $env:ComSpec /c 'netstat -ano' 2>$null
            $conns2 = New-Object System.Collections.ArrayList
            foreach ($ln in @($netstatOut)) {
                $m = [regex]::Match([string]$ln, '^\s*TCP\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)\s*$')
                if (-not $m.Success) { continue }
                $le = $m.Groups[1].Value; $re = $m.Groups[2].Value; $st = $m.Groups[3].Value; $opid = [int]$m.Groups[4].Value
                $pname = $null; $ppath = $null
                if ($procMap2.ContainsKey($opid)) { $po = $procMap2[$opid]; $pname = $po.ProcessName; try { $ppath = $po.Path } catch { } }
                [void]$conns2.Add((New-Object PSObject -Property @{
                    LocalEndpoint = $le; RemoteEndpoint = $re; State = $st; OwningProcess = $opid
                    ProcessName = $pname; ProcessPath = $ppath
                    LocalAddress = ($le -replace ':\d+$', ''); LocalPort = ($le -replace '^.*:', '')
                    RemoteAddress = ($re -replace ':\d+$', ''); RemotePort = ($re -replace '^.*:', '')
                    CreationTimeLocal = $null; TimestampUTC = Get-NowUtcString
                }))
            }
            if ($conns2.Count -gt 0) {
                Export-ObjectData -Data $conns2 -BaseName '51_tcp_connections' -Category 'Network'
                Write-ForensicLog -Message ('Network: {0} conexiones TCP via netstat (compatibilidad PowerShell {1}).' -f $conns2.Count, $PSVersionTable.PSVersion.Major)
            } else {
                Register-MissingEvidence -Evidence 'Conexiones TCP' -Reason 'netstat no devolvio conexiones'
            }
        } catch { Write-ForensicLog -Level DEBUG -Message ('Fallback netstat fallo: {0}' -f $_.Exception.Message) }
    }
    Write-ForensicLog -Message 'Modulo Network completado.'
}




function Invoke-ModuleVolatile {
    if (-not (Test-ModuleSelected 'Volatile') -or -not $IncludeVolatileData) { return }
    Write-ForensicLog -Message '--- MODULO Volatile ---'
    Register-Source 'Win32_Process (procesos con linea de comandos) / qwinsta / tasklist'

    
    $procs = Get-CimOrWmi -ClassName 'Win32_Process'
    if ($procs) {
        $pList = New-Object System.Collections.ArrayList
        foreach ($pr in @($procs)) {
            if ($null -eq $pr) { continue }
            $ownerUser = $null; $ownerDom = $null
            try {
                if ((Test-CommandAvailable 'Invoke-CimMethod') -and ($pr.PSObject.TypeNames[0] -match 'CimInstance')) {
                    $o = Invoke-CimMethod -InputObject $pr -MethodName GetOwner -ErrorAction Stop
                    $ownerUser = $o.User; $ownerDom = $o.Domain
                } else {
                    $o = $pr.GetOwner()
                    $ownerUser = $o.User; $ownerDom = $o.Domain
                }
            } catch { }
            $created = $null
            try {
                if ($pr.CreationDate -is [datetime]) { $created = $pr.CreationDate }
                elseif ($pr.CreationDate) { $created = [Management.ManagementDateTimeConverter]::ToDateTime($pr.CreationDate) }
            } catch { }
            $exeHash = $null; $signed = $null
            if ($pr.ExecutablePath -and (Test-Path -LiteralPath $pr.ExecutablePath)) {
                $exeHash = Get-EvidenceFileHash -Path $pr.ExecutablePath -Algorithm SHA256
                if (Test-CommandAvailable 'Get-AuthenticodeSignature') {
                    try { $signed = (Get-AuthenticodeSignature -LiteralPath $pr.ExecutablePath -ErrorAction Stop).Status.ToString() } catch { }
                }
            }
            [void]$pList.Add((New-Object PSObject -Property @{
                ProcessId = $pr.ProcessId; ParentProcessId = $pr.ParentProcessId
                ProcessName = $pr.Name; ExecutablePath = $pr.ExecutablePath
                CommandLine = $pr.CommandLine
                Owner = if ($ownerUser) { ('{0}\{1}' -f $ownerDom, $ownerUser) } else { $null }
                CreatedLocal = if ($created) { $created.ToString($script:TsFmt) } else { $null }
                CreatedUTC   = if ($created) { $created.ToUniversalTime().ToString($script:TsFmt) } else { $null }
                ExeSHA256 = $exeHash; Signature = $signed
                CollectedUTC = Get-NowUtcString
            }))
        }
        Export-ObjectData -Data $pList -BaseName '60_running_processes' -Category 'Volatile'
    }

    
    if (Test-CommandAvailable 'qwinsta.exe') {
        Invoke-NativeTool -Executable 'qwinsta.exe' -OutputFile (Join-Path $script:Paths.ParsedTXT 'sessions_qwinsta.txt') -Description 'Sesiones de terminal activas' | Out-Null
        Register-Evidence -Path (Join-Path $script:Paths.ParsedTXT 'sessions_qwinsta.txt') -Category 'Volatile' -SourceDescription 'qwinsta'
    } elseif (Test-CommandAvailable 'query.exe') {
        Invoke-NativeTool -Executable 'query.exe' -Arguments 'session' -OutputFile (Join-Path $script:Paths.ParsedTXT 'sessions_query.txt') -Description 'Sesiones (fallback query session)' | Out-Null
        Register-Evidence -Path (Join-Path $script:Paths.ParsedTXT 'sessions_query.txt') -Category 'Volatile' -SourceDescription 'query session'
    } else {
        Register-MissingEvidence -Evidence 'Sesiones interactivas (qwinsta)' -Reason 'Herramienta no presente en este SKU'
    }

    
    Invoke-NativeTool -Executable 'tasklist.exe' -Arguments '/v /fo csv' -OutputFile (Join-Path $script:Paths.ParsedTXT 'tasklist_verbose.csv') -Description 'Procesos (vista nativa)' | Out-Null
    Invoke-NativeTool -Executable 'tasklist.exe' -Arguments '/svc /fo csv' -OutputFile (Join-Path $script:Paths.ParsedTXT 'tasklist_services.csv') -Description 'Servicios por proceso' | Out-Null
    foreach ($f in 'tasklist_verbose.csv','tasklist_services.csv') {
        Register-Evidence -Path (Join-Path $script:Paths.ParsedTXT $f) -Category 'Volatile' -SourceDescription 'tasklist.exe'
    }
    Write-ForensicLog -Message 'Modulo Volatile completado. La captura de memoria RAM completa requiere herramienta especializada (no incluida por diseno).'
}




function Invoke-ModulePersistence {
    if (-not (Test-ModuleSelected 'Persistence') -or -not $IncludePersistenceArtifacts) { return }
    Write-ForensicLog -Message '--- MODULO Persistence ---'
    $pDir = $script:Paths.RawPersist
    Register-Source 'schtasks / sc / WMI EventConsumer / carpetas de inicio / GPO scripts'

    
    Invoke-NativeTool -Executable 'schtasks.exe' -Arguments '/query /v /fo CSV' -OutputFile (Join-Path $script:Paths.ParsedTXT 'tasks_schtasks.csv') -Description 'Tareas programadas (verbose CSV)' | Out-Null
    Register-Evidence -Path (Join-Path $script:Paths.ParsedTXT 'tasks_schtasks.csv') -Category 'Persistence' -SourceDescription 'schtasks /query /v'
    $taskRoot = Join-Path (Get-WinEnvPath SystemRoot) 'System32\Tasks'
    if (Test-Path -LiteralPath $taskRoot) {
        foreach ($tf in @(Get-ChildItem -LiteralPath $taskRoot -Recurse -Force -File -ErrorAction SilentlyContinue)) {
            $rel = $tf.FullName.Substring($taskRoot.Length).TrimStart('\')
            Copy-EvidenceFile -SourcePath $tf.FullName -DestinationPath (Join-Path (Join-Path $pDir 'Tasks_XML') $rel) -Category 'Persistence' -Notes 'Definicion XML de tarea programada' | Out-Null
        }
    }

    
    
    $svcInstall = @{}   
    if (Test-CommandAvailable 'Get-WinEvent') {
        foreach ($chId in @(@{Ch='System';Id=7045},@{Ch='Security';Id=4697})) {
            try {
                foreach ($e in @(Get-WinEvent -FilterHashtable @{ LogName=$chId.Ch; Id=$chId.Id } -MaxEvents 2000 -ErrorAction Stop)) {
                    $d = Get-EventDataHash $e
                    $svcName = $(if ($d['ServiceName']) { $d['ServiceName'] } else { $d['SubjectServiceName'] })
                    if (-not $svcName) { continue }
                    if (-not $svcInstall.ContainsKey($svcName)) {
                        $svcInstall[$svcName] = @{ WhenUtc=$e.TimeCreated.ToUniversalTime().ToString($script:TsFmt); WhenLocal=(ConvertTo-MadridTimeString $e.TimeCreated); ImagePath=$($d['ImagePath']); Account=$($d['AccountName']); EventId=$chId.Id }
                    }
                }
            } catch { }
        }
    }
    $svcs = Get-CimOrWmi -ClassName 'Win32_Service'
    if ($svcs) {
        $sList = @($svcs | ForEach-Object {
            $assessment = 'Ruta estandar del sistema'
            if (-not $_.PathName) { $assessment = 'Sin ruta declarada (revisar)' }
            elseif ($_.PathName -match '(?i)\\Users\\|\\Temp\\|\\AppData\\') { $assessment = 'INDICADOR: ejecutable en ruta de usuario/temporal (revisar)' }
            elseif ($_.PathName -match '(?i)\\ProgramData\\[^"]*\.exe') { $assessment = 'INDICADOR: ejecutable bajo ProgramData (revisar)' }
            elseif ($_.PathName -match '^["]?\\\\') { $assessment = 'INDICADOR: ejecutable en ruta de red UNC (revisar)' }
            $suspicious = ($assessment -like 'INDICADOR*' -or $assessment -like 'Sin ruta*')
            $inst = $svcInstall[$_.Name]
            New-Object PSObject -Property @{
                InstaladoUTC = $(if ($inst) { $inst.WhenUtc } else { $null })
                InstaladoLocal = $(if ($inst) { $inst.WhenLocal } else { $null })
                InstalacionEventId = $(if ($inst) { $inst.EventId } else { $null })
                Name = $_.Name; DisplayName = $_.DisplayName; State = $_.State
                StartMode = $_.StartMode; StartName = $_.StartName; PathName = $_.PathName
                PathAssessment = $assessment; SuspiciousPathFlag = $suspicious
                CollectedUTC = Get-NowUtcString
            }
        })
        Export-ObjectData -Data $sList -BaseName '70_services' -Category 'Persistence'
    }

    
    $wmiNs = 'root\subscription'
    $consumers = Get-CimOrWmi -ClassName '__EventConsumer' -Namespace $wmiNs
    $filters   = Get-CimOrWmi -ClassName '__EventFilter' -Namespace $wmiNs
    $bindings  = Get-CimOrWmi -ClassName '__FilterToConsumerBinding' -Namespace $wmiNs
    $wmiPersist = New-Object System.Collections.ArrayList
    foreach ($c in @($consumers)) {
        if ($null -eq $c) { continue }
        $cmdOrScript = $(if ($c.CommandLineTemplate) { $c.CommandLineTemplate } elseif ($c.ScriptText) { $c.ScriptText } elseif ($c.ExecutablePath) { $c.ExecutablePath } else { $null })
        [void]$wmiPersist.Add((New-Object PSObject -Property @{
            Type='Consumer'; Name=$c.Name; Class=$c.PSObject.TypeNames[0]
            CommandOrScript = $cmdOrScript
            Detail = $cmdOrScript
            CreatorSID = $(try { $c.CreatorSID } catch { $null })
            CollectedUTC = Get-NowUtcString }))
    }
    foreach ($f in @($filters)) {
        if ($null -eq $f) { continue }
        [void]$wmiPersist.Add((New-Object PSObject -Property @{ Type='Filter'; Name=$f.Name; Class='__EventFilter'; Query=$f.Query; Detail=$f.Query; Namespace=$(try { $f.EventNamespace } catch { $null }); CollectedUTC=Get-NowUtcString }))
    }
    foreach ($b in @($bindings)) {
        if ($null -eq $b) { continue }
        [void]$wmiPersist.Add((New-Object PSObject -Property @{ Type='Binding'; Name=$null; Class='__FilterToConsumerBinding'; Detail=('{0} -> {1}' -f $b.Filter, $b.Consumer); Filter=$(try{$b.Filter}catch{$null}); Consumer=$(try{$b.Consumer}catch{$null}); CollectedUTC=Get-NowUtcString }))
    }
    if ($wmiPersist.Count -gt 0) { Export-ObjectData -Data $wmiPersist -BaseName '71_wmi_subscriptions' -Category 'Persistence' }

    
    $startupPaths = New-Object System.Collections.ArrayList
    [void]$startupPaths.Add((Join-Path (Get-WinEnvPath ProgramData) 'Microsoft\Windows\Start Menu\Programs\Startup'))
    $profiles = Get-CimOrWmi -ClassName 'Win32_UserProfile'
    foreach ($p in @($profiles)) {
        if ($null -eq $p -or $p.Special -or -not $p.LocalPath) { continue }
        [void]$startupPaths.Add((Join-Path $p.LocalPath 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'))
    }
    foreach ($sp in $startupPaths) {
        if (-not (Test-Path -LiteralPath $sp)) { continue }
        foreach ($f in @(Get-ChildItem -LiteralPath $sp -Force -File -ErrorAction SilentlyContinue)) {
            $safe = ($sp -replace '[:\\]','_')
            Copy-EvidenceFile -SourcePath $f.FullName -DestinationPath (Join-Path (Join-Path $pDir 'Startup') ($safe + '__' + $f.Name)) -Category 'Persistence' -Notes 'Elemento de carpeta de inicio' | Out-Null
        }
    }
    $gpoScripts = Join-Path (Get-WinEnvPath SystemRoot) 'System32\GroupPolicy'
    if (Test-Path -LiteralPath $gpoScripts) {
        foreach ($f in @(Get-ChildItem -LiteralPath $gpoScripts -Recurse -Force -File -ErrorAction SilentlyContinue)) {
            $rel = $f.FullName.Substring($gpoScripts.Length).TrimStart('\')
            Copy-EvidenceFile -SourcePath $f.FullName -DestinationPath (Join-Path (Join-Path $pDir 'GroupPolicy_Local') $rel) -Category 'Persistence' -Notes 'Scripts/config GPO local (logon/logoff/startup/shutdown)' | Out-Null
        }
    }

    
    
    
    
    
    if ($script:PSMajor -ge 3) {
        $adsCsv = Join-Path $script:Paths.ParsedCSV '72_alternate_data_streams.csv'
        $dlCsv  = Join-Path $script:Paths.ParsedCSV '73_download_origin.csv'
        $adsCount = 0; $dlCount = 0
        
        
        
        $adsBuf = New-Object System.Collections.ArrayList; $dlBuf = New-Object System.Collections.ArrayList
        $flushAds = {
            if ($dlBuf.Count -gt 0) { $dlBuf | Export-Csv -LiteralPath $dlCsv -NoTypeInformation -Encoding UTF8 -Append; $dlBuf.Clear() }
            if ($adsBuf.Count -gt 0) { $adsBuf | Export-Csv -LiteralPath $adsCsv -NoTypeInformation -Encoding UTF8 -Append; $adsBuf.Clear() }
        }
        $adsSkipRe = '(?i)(\\AppData\\Local\\Microsoft\\Windows\\(INetCache|WebCache)|\\User Data\\[^\\]+\\(Cache|Code Cache|GPUCache|Service Worker|DawnCache|ShaderCache)|\\cache2\\|\\AppData\\Local\\Packages\\|\\node_modules\\|\\\.git\\|\\AppData\\Local\\Microsoft\\(VisualStudio|Teams|OneDrive)\\|\\AppData\\Local\\(JetBrains|Docker|Steam|Spotify|Adobe|NVIDIA)\\)'
        $adsPartial = New-Object System.Collections.ArrayList
        foreach ($p in @($profiles)) {
            if ($null -eq $p -or $p.Special -or -not $p.LocalPath) { continue }
            if (-not (Test-Path -LiteralPath $p.LocalPath)) { continue }
            $sw = [System.Diagnostics.Stopwatch]::StartNew(); $seenA = 0; $lastProg = Get-Date; $cutA = $false
            $stack = New-Object System.Collections.Stack; $stack.Push($p.LocalPath)
            try {
                while ($stack.Count -gt 0) {
                    $dir = $stack.Pop()
                    if ($MaxScanSecondsPerRoot -gt 0 -and $sw.Elapsed.TotalSeconds -gt $MaxScanSecondsPerRoot) { $cutA = $true; break }
                    if (((Get-Date) - $lastProg).TotalSeconds -ge 20) { Write-Host ('   ... ADS/MOTW {0}: {1} archivos, {2} con origen web, {3} s' -f $p.LocalPath, $seenA, $dlCount, [int]$sw.Elapsed.TotalSeconds) -ForegroundColor DarkGray; $lastProg = Get-Date }
                    $subs = $null; try { $subs = [System.IO.Directory]::GetDirectories($dir) } catch { }
                    if ($subs) { foreach ($sd in $subs) { if ($sd -match $adsSkipRe) { continue }; try { if (([int][System.IO.File]::GetAttributes($sd) -band 0x400) -ne 0) { continue } } catch { continue }; $stack.Push($sd) } }
                    $files = $null; try { $files = [System.IO.Directory]::GetFiles($dir) } catch { }
                    if (-not $files) { continue }
                    foreach ($fp in $files) {
                        $seenA++
                        $streams = $null
                        try { $streams = Get-Item -LiteralPath $fp -Stream * -Force -ErrorAction Stop } catch { }
                        if (-not $streams) { continue }
                        $lwt = $null
                        foreach ($st in @($streams)) {
                            if ($null -eq $st -or $st.Stream -eq ':$DATA') { continue }
                            if (-not $lwt) { try { $lwt = [System.IO.File]::GetLastWriteTimeUtc($fp) } catch { $lwt = [datetime]::MinValue } }
                            if ($st.Stream -eq 'Zone.Identifier') {
                                if ($dlCount -lt 8000) {
                                    $content = $null
                                    try { $content = (Get-Content -LiteralPath $fp -Stream 'Zone.Identifier' -ErrorAction Stop) -join '; ' } catch { }
                                    $zoneId = $null; $hostUrl = $null; $refUrl = $null; $lwpfn = $null
                                    if ($content) {
                                        $m = [regex]::Match($content, '(?im)ZoneId=(\d+)'); if ($m.Success) { $zoneId = $m.Groups[1].Value }
                                        $m = [regex]::Match($content, '(?im)HostUrl=([^;]+)'); if ($m.Success) { $hostUrl = $m.Groups[1].Value.Trim() }
                                        $m = [regex]::Match($content, '(?im)ReferrerUrl=([^;]+)'); if ($m.Success) { $refUrl = $m.Groups[1].Value.Trim() }
                                        $m = [regex]::Match($content, '(?im)LastWriterPackageFamilyName=([^;]+)'); if ($m.Success) { $lwpfn = $m.Groups[1].Value.Trim() }
                                    }
                                    if ($zoneId -or $hostUrl -or $refUrl) {
                                        $zn = switch ([string]$zoneId) { '3' {'Internet'} '4' {'Sitios restringidos'} '2' {'Intranet de confianza'} '1' {'Intranet local'} '0' {'Equipo local'} default { $zoneId } }
                                        [void]$dlBuf.Add((New-Object PSObject -Property @{
                                            FilePath = $fp; Zona = $zn; HostUrl = $hostUrl; ReferrerUrl = $refUrl
                                            LastWriterApp = $lwpfn
                                            TimestampUTC = $lwt.ToString($script:TsFmt)
                                            TimestampSource = 'LastWrite del archivo (aprox. a la descarga)'
                                            Confidence = 'Aproximada (la fecha exacta de descarga se correlaciona con el historial del navegador, USN o Prefetch)'
                                        }))
                                        $dlCount++
                                    }
                                }
                                continue
                            }
                            $preview = $null
                            if ($st.Length -gt 0 -and $st.Length -le 2048) {
                                try { $preview = ((Get-Content -LiteralPath $fp -Stream $st.Stream -ErrorAction Stop) -join ' '); if ($preview.Length -gt 200) { $preview = $preview.Substring(0,200) } } catch { }
                            }
                            [void]$adsBuf.Add((New-Object PSObject -Property @{
                                FilePath = $fp; StreamName = $st.Stream; StreamLength = $st.Length
                                ModifiedUTC = $lwt.ToString($script:TsFmt)
                                ContentPreview = $preview
                                Note = 'ADS distinto de Zone.Identifier: posible ocultacion de datos/codigo (revisar)'
                            }))
                            $adsCount++
                        }
                        if (($dlBuf.Count + $adsBuf.Count) -ge 2000) { & $flushAds }
                    }
                }
            } catch { }
            & $flushAds
            $sw.Stop()
            if ($cutA) { [void]$adsPartial.Add($p.LocalPath); Write-ForensicLog -Level WARN -Message ('Escaneo ADS/MOTW de {0} CORTADO por presupuesto de tiempo ({1} s): {2} archivos vistos. Parcial.' -f $p.LocalPath, $MaxScanSecondsPerRoot, $seenA) }
            else { Write-ForensicLog -Message ('Escaneo ADS/MOTW de {0}: {1} archivos vistos, {2} s.' -f $p.LocalPath, $seenA, [int]$sw.Elapsed.TotalSeconds) }
        }
        if ($adsPartial.Count -gt 0) { Register-MissingEvidence -Evidence 'Escaneo completo de Zone.Identifier/ADS' -Reason ('Cortado por presupuesto de tiempo en: {0}. Listado parcial; el resto se obtiene de la imagen offline.' -f ($adsPartial -join ', ')) -Status 'REQUIRES_OFFLINE_ACQUISITION' }
        if ($dlCount -gt 0) {
            Register-Evidence -Path $dlCsv -Category 'Persistence' -SourceDescription 'Zone.Identifier (Mark-of-the-Web)' -Notes ('{0} archivos con origen de descarga registrado' -f $dlCount)
            Write-ForensicLog -Message ('Origen de descarga (Zone.Identifier): {0} archivos con procedencia web.' -f $dlCount)
        }
        if ($adsCount -gt 0) {
            Register-Evidence -Path $adsCsv -Category 'Persistence' -SourceDescription 'ADS scan' -Notes ('{0} streams anomalos' -f $adsCount)
            Write-ForensicLog -Level WARN -Message ('Detectados {0} Alternate Data Streams no estandar (indicador, no conclusion).' -f $adsCount)
        }
    }
    Write-ForensicLog -Message 'Modulo Persistence completado.'
}













function ConvertFrom-RecycleBinIndex {
    



    param([Parameter(Mandatory = $true)][string]$Path)
    try {
        $b = [System.IO.File]::ReadAllBytes($Path)
        if ($b.Length -lt 24) { return $null }
        $ver  = [BitConverter]::ToInt64($b, 0)
        $size = [BitConverter]::ToInt64($b, 8)
        $ft   = [BitConverter]::ToInt64($b, 16)
        $deleted = $null
        try { if ($ft -gt 0) { $deleted = [DateTime]::FromFileTimeUtc($ft) } } catch { }
        $origPath = $null
        if ($ver -eq 2) {
            if ($b.Length -ge 28) {
                $pathBytes = $b[28..($b.Length - 1)]
                $origPath  = [System.Text.Encoding]::Unicode.GetString($pathBytes)
            }
        } else {
            $pathBytes = $b[24..($b.Length - 1)]
            $origPath  = [System.Text.Encoding]::Unicode.GetString($pathBytes)
        }
        if ($origPath) { $origPath = $origPath.Split([char]0)[0] }
        return (New-Object PSObject -Property @{
            Version = $ver; SizeBytes = $size; DeletedUTC = $deleted; OriginalPath = $origPath
        })
    } catch {
        Write-ForensicLog -Level DEBUG -Message ('No se pudo parsear indice $I {0}: {1}' -f $Path, $_.Exception.Message)
        return $null
    }
}

function Resolve-LnkTarget {
    
    param([Parameter(Mandatory = $true)][string]$LnkPath)
    try {
        if (-not $script:WshShell) { $script:WshShell = New-Object -ComObject WScript.Shell }
        $sc = $script:WshShell.CreateShortcut($LnkPath)
        return (New-Object PSObject -Property @{
            Target = $sc.TargetPath; Args = $sc.Arguments; WorkingDir = $sc.WorkingDirectory
        })
    } catch { return $null }
}

function Get-DeletedFileRecord {
    
    param([hashtable]$Map, [string]$Path, [string]$Name)
    $key = $null
    if ($Path) { $key = $Path.ToLowerInvariant() }
    elseif ($Name) { $key = 'name::' + $Name.ToLowerInvariant() }
    else { return $null }
    if (-not $Map.ContainsKey($key)) {
        $ext = ''
        if ($Name) { try { $ext = [System.IO.Path]::GetExtension($Name) } catch { } }
        elseif ($Path) { try { $ext = [System.IO.Path]::GetExtension($Path) } catch { } }
        $dir = ''
        if ($Path) { try { $dir = [System.IO.Path]::GetDirectoryName($Path) } catch { } }
        $vol = ''
        if ($Path -and $Path.Length -ge 2 -and $Path[1] -eq ':') { $vol = $Path.Substring(0,2) }
        $Map[$key] = New-Object PSObject -Property @{
            Name = $Name; Extension = $ext; Type = $ext.TrimStart('.').ToUpperInvariant()
            OriginalPath = $Path; Directory = $dir; Volume = $vol
            SizeBytes = $null; User = $null; SID = $null
            CreatedUTC = $null; ModifiedUTC = $null; LastAccessUTC = $null; DeletedUTC = $null
            DeletionMethod = $null; Status = $null; Recoverability = $null
            SHA256 = $null; Confidence = $null; Notes = $null
            
            HasI = $false; HasR = $false; HasDeleteCmd = $false; Has4660 = $false
            HasRef = $false; RefAbsent = $false
            HasUsnEmptied = $false; HasUsnDirect = $false; HasUsnToBin = $false
            Evidence = (New-Object System.Collections.ArrayList)
        }
    }
    $r = $Map[$key]
    if (-not $r.Name -and $Name) { $r.Name = $Name }
    if (-not $r.OriginalPath -and $Path) {
        $r.OriginalPath = $Path
        try { $r.Directory = [System.IO.Path]::GetDirectoryName($Path) } catch { }
        if ($Path.Length -ge 2 -and $Path[1] -eq ':') { $r.Volume = $Path.Substring(0,2) }
    }
    return $r
}

function Add-DeletedEvidence {
    
    param($Record, [string]$Source, $TimestampUTC, [string]$Artifact, [string]$Info, [string]$Event, [string]$Confidence, [System.Collections.ArrayList]$Timeline)
    [void]$Record.Evidence.Add((New-Object PSObject -Property @{
        Source = $Source; TimestampUTC = $TimestampUTC; Artifact = $Artifact; Info = $Info; Confidence = $Confidence
    }))
    if ($null -ne $Timeline) {
        $tsLocal = $null
        if ($TimestampUTC) { try { $tsLocal = ([datetime]$TimestampUTC).ToLocalTime().ToString($script:TsFmt) } catch { } }
        [void]$Timeline.Add((New-Object PSObject -Property @{
            TimestampUTC = $TimestampUTC; TimestampLocal = $tsLocal; Event = $Event
            File = $Record.Name; Path = $Record.OriginalPath; User = $Record.User
            Source = $Source; Confidence = $Confidence; Notes = $Info
        }))
    }
}

$script:UsnReaderReady = $false
$script:UsnParentCache = @{}
function Initialize-UsnReader {
    





    if ($script:UsnReaderReady) { return $true }
    if ('ForensicUsn' -as [type]) { $script:UsnReaderReady = $true; return $true }
    try {
        Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
public static class ForensicUsn {
    const uint GENERIC_READ = 0x80000000;
    const uint FILE_SHARE_READ = 0x1, FILE_SHARE_WRITE = 0x2;
    const uint OPEN_EXISTING = 3;
    const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    const uint FSCTL_QUERY_USN_JOURNAL = 0x000900f4;
    const uint FSCTL_READ_USN_JOURNAL  = 0x000900bb;
    const uint R_FILE_DELETE = 0x00000200;
    const uint R_RENAME_OLD  = 0x00001000;
    const uint R_RENAME_NEW  = 0x00002000;
    static readonly IntPtr INVALID = new IntPtr(-1);

    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr sec, uint disp, uint flags, IntPtr templ);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool DeviceIoControl(IntPtr h, uint code, IntPtr inBuf, int inSize, IntPtr outBuf, int outSize, out int bytesRet, IntPtr ov);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    static extern int GetFinalPathNameByHandleW(IntPtr h, StringBuilder buf, int bufLen, int flags);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr OpenFileById(IntPtr volHint, ref FILE_ID_DESCRIPTOR id, uint access, uint share, IntPtr sec, uint flags);

    [StructLayout(LayoutKind.Sequential)]
    struct USN_JOURNAL_DATA { public ulong UsnJournalID; public long FirstUsn; public long NextUsn; public long LowestValidUsn; public long MaxUsn; public ulong MaximumSize; public ulong AllocationDelta; }
    [StructLayout(LayoutKind.Sequential)]
    struct READ_USN_JOURNAL_DATA { public long StartUsn; public uint ReasonMask; public uint ReturnOnlyOnClose; public ulong Timeout; public ulong BytesToWaitFor; public ulong UsnJournalID; }
    [StructLayout(LayoutKind.Sequential)]
    struct FILE_ID_DESCRIPTOR { public uint dwSize; public int Type; public long Id; public long Id2; }

    static IntPtr OpenVolume(string volume) {
        string path = "\\\\.\\" + volume.TrimEnd('\\');
        return CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero);
    }

    public static long[] QueryJournal(string volume) {
        IntPtr h = OpenVolume(volume);
        if (h == INVALID) return null;
        try {
            int size = Marshal.SizeOf(typeof(USN_JOURNAL_DATA));
            IntPtr buf = Marshal.AllocHGlobal(size);
            try {
                int br;
                if (!DeviceIoControl(h, FSCTL_QUERY_USN_JOURNAL, IntPtr.Zero, 0, buf, size, out br, IntPtr.Zero)) return null;
                USN_JOURNAL_DATA d = (USN_JOURNAL_DATA)Marshal.PtrToStructure(buf, typeof(USN_JOURNAL_DATA));
                return new long[] { (long)d.UsnJournalID, d.FirstUsn, d.NextUsn, d.LowestValidUsn, d.MaxUsn };
            } finally { Marshal.FreeHGlobal(buf); }
        } finally { CloseHandle(h); }
    }

    public static List<string> ReadDeletions(string volume, long sinceFileTimeUtc, int maxRecords, int maxIterations) {
        var outList = new List<string>();
        IntPtr h = OpenVolume(volume);
        if (h == INVALID) return outList;
        try {
            int qsize = Marshal.SizeOf(typeof(USN_JOURNAL_DATA));
            IntPtr qbuf = Marshal.AllocHGlobal(qsize);
            USN_JOURNAL_DATA jd;
            try {
                int br0;
                if (!DeviceIoControl(h, FSCTL_QUERY_USN_JOURNAL, IntPtr.Zero, 0, qbuf, qsize, out br0, IntPtr.Zero)) return outList;
                jd = (USN_JOURNAL_DATA)Marshal.PtrToStructure(qbuf, typeof(USN_JOURNAL_DATA));
            } finally { Marshal.FreeHGlobal(qbuf); }

            READ_USN_JOURNAL_DATA rd = new READ_USN_JOURNAL_DATA();
            rd.StartUsn = jd.LowestValidUsn;
            rd.ReasonMask = R_FILE_DELETE | R_RENAME_OLD | R_RENAME_NEW;
            rd.ReturnOnlyOnClose = 0; rd.Timeout = 0; rd.BytesToWaitFor = 0; rd.UsnJournalID = jd.UsnJournalID;

            int rdSize = Marshal.SizeOf(typeof(READ_USN_JOURNAL_DATA));
            IntPtr rdBuf = Marshal.AllocHGlobal(rdSize);
            int bufSize = 65536;
            IntPtr outBuf = Marshal.AllocHGlobal(bufSize);
            try {
                int iter = 0;
                while (iter++ < maxIterations && outList.Count < maxRecords) {
                    Marshal.StructureToPtr(rd, rdBuf, false);
                    int bytesRet;
                    if (!DeviceIoControl(h, FSCTL_READ_USN_JOURNAL, rdBuf, rdSize, outBuf, bufSize, out bytesRet, IntPtr.Zero)) break;
                    if (bytesRet <= 8) break;
                    long nextUsn = Marshal.ReadInt64(outBuf, 0);
                    int offset = 8;
                    while (offset < bytesRet) {
                        int recLen = Marshal.ReadInt32(outBuf, offset);
                        if (recLen <= 0) break;
                        ushort major = (ushort)Marshal.ReadInt16(outBuf, offset + 4);
                        if (major == 2) {
                            long frn  = Marshal.ReadInt64(outBuf, offset + 8);
                            long pfrn = Marshal.ReadInt64(outBuf, offset + 16);
                            long usn  = Marshal.ReadInt64(outBuf, offset + 24);
                            long ts   = Marshal.ReadInt64(outBuf, offset + 32);
                            uint reason = (uint)Marshal.ReadInt32(outBuf, offset + 40);
                            ushort nameLen = (ushort)Marshal.ReadInt16(outBuf, offset + 56);
                            ushort nameOff = (ushort)Marshal.ReadInt16(outBuf, offset + 58);
                            string name = "";
                            if (nameLen > 0 && (offset + nameOff + nameLen) <= bytesRet) {
                                name = Marshal.PtrToStringUni((IntPtr)(outBuf.ToInt64() + offset + nameOff), nameLen / 2);
                            }
                            if (ts >= sinceFileTimeUtc) {
                                outList.Add(usn.ToString() + "\t" + ((ulong)frn).ToString() + "\t" + ((ulong)pfrn).ToString() + "\t0x" + reason.ToString("x8") + "\t" + ts.ToString() + "\t" + name);
                                if (outList.Count >= maxRecords) break;
                            }
                        }
                        offset += recLen;
                    }
                    if (nextUsn == rd.StartUsn) break;
                    rd.StartUsn = nextUsn;
                }
            } finally { Marshal.FreeHGlobal(rdBuf); Marshal.FreeHGlobal(outBuf); }
        } finally { CloseHandle(h); }
        return outList;
    }

    public static string ResolveParentPath(string volume, long parentFrn) {
        IntPtr vh = OpenVolume(volume);
        if (vh == INVALID) return null;
        try {
            FILE_ID_DESCRIPTOR id = new FILE_ID_DESCRIPTOR();
            id.dwSize = (uint)Marshal.SizeOf(typeof(FILE_ID_DESCRIPTOR));
            id.Type = 0; id.Id = parentFrn; id.Id2 = 0;
            IntPtr fh = OpenFileById(vh, ref id, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, FILE_FLAG_BACKUP_SEMANTICS);
            if (fh == INVALID) return null;
            try {
                StringBuilder sb = new StringBuilder(1024);
                int n = GetFinalPathNameByHandleW(fh, sb, sb.Capacity, 0);
                if (n <= 0) return null;
                string p = sb.ToString();
                if (p.StartsWith("\\\\?\\")) { p = p.Substring(4); }
                return p;
            } finally { CloseHandle(fh); }
        } finally { CloseHandle(vh); }
    }
}
'@
        $script:UsnReaderReady = $true
        return $true
    } catch {
        Write-ForensicLog -Level DEBUG -Message ('No se pudo compilar el lector USN (se usara via offline): {0}' -f $_.Exception.Message)
        return $false
    }
}

function Resolve-UsnParentPath {
    
    param([string]$Volume, [long]$ParentFrn)
    $key = $Volume + '|' + $ParentFrn
    if ($script:UsnParentCache.ContainsKey($key)) { return $script:UsnParentCache[$key] }
    $p = $null
    try { $p = [ForensicUsn]::ResolveParentPath($Volume, $ParentFrn) } catch { }
    $script:UsnParentCache[$key] = $p
    return $p
}

function Get-UsnDeletionRecords {
    




    param([string]$Volume, [datetime]$SinceUtc, [int]$Max = 20000, [int]$MaxIter = 200000)
    if (-not (Initialize-UsnReader)) { return $null }
    $sinceFt = 0
    try { $sinceFt = $SinceUtc.ToFileTimeUtc() } catch { $sinceFt = 0 }
    $lines = $null
    try { $lines = [ForensicUsn]::ReadDeletions($Volume, $sinceFt, $Max, $MaxIter) } catch {
        Write-ForensicLog -Level DEBUG -Message ('Lectura USN fallida: {0}' -f $_.Exception.Message); return $null
    }
    if ($null -eq $lines) { return $null }
    $recs = New-Object System.Collections.ArrayList
    foreach ($ln in $lines) {
        $f = $ln -split "`t"
        if ($f.Count -lt 6) { continue }
        $reason = 0; try { $reason = [Convert]::ToUInt32($f[3], 16) } catch { }
        $ts = $null; try { $ts = [DateTime]::FromFileTimeUtc([long]$f[4]) } catch { }
        [void]$recs.Add((New-Object PSObject -Property @{
            Usn = [long]$f[0]; Frn = [long]$f[1]; ParentFrn = [long]$f[2]
            Reason = $reason; TimeStampUTC = $ts; FileName = $f[5]
        }))
    }
    return $recs
}


function ConvertFrom-FsutilUsnText {
    






    param([string[]]$Lines, [int]$Max = 8000)
    $recs = New-Object System.Collections.ArrayList
    if (-not $Lines) { return $recs }
    $n = $Lines.Count
    for ($i = 0; $i -lt $n; $i++) {
        
        $mh = [regex]::Match($Lines[$i], ':\s*(0x[0-9A-Fa-f]{6,16})\s*:\s*\S')
        if (-not $mh.Success) { continue }
        $val = 0
        try { $val = [Convert]::ToUInt32(($mh.Groups[1].Value -replace '^0x', ''), 16) } catch { continue }
        $isDel    = (($val -band 0x200) -ne 0)
        $isRenOld = (($val -band 0x1000) -ne 0)
        $isRenNew = (($val -band 0x2000) -ne 0)
        if (-not ($isDel -or $isRenOld -or $isRenNew)) { continue }
        
        $looksReason = ((($val -band 0x80000000) -ne 0) -or ($val -lt 0x40000000 -and $val -ge 0x200))
        if (-not $looksReason) { continue }
        $fname = $null; $ts = $null
        
        for ($j = $i - 1; $j -ge [math]::Max(0, $i - 6); $j--) {
            if ($Lines[$j] -match '^\s*$') { break }
            $mv = [regex]::Match($Lines[$j], ':\s*(.+?)\s*$')
            if (-not $mv.Success) { continue }
            $v = $mv.Groups[1].Value.Trim()
            if ($v -match '\.[A-Za-z0-9]{1,8}$' -and $v -notmatch '^0x' -and $v -notmatch '\d{1,2}:\d{2}') { $fname = $v; break }
        }
        
        for ($j = $i + 1; $j -le [math]::Min($n - 1, $i + 4); $j++) {
            if ($Lines[$j] -match '^\s*$') { break }
            $mv = [regex]::Match($Lines[$j], ':\s*(.+?)\s*$')
            if (-not $mv.Success) { continue }
            $v = $mv.Groups[1].Value.Trim()
            if ($v -match '\d{1,4}[/\-]\d{1,2}[/\-]\d{1,4}' -and $v -match '\d{1,2}:\d{2}') { $ts = $v; break }
        }
        if (-not $fname) { continue }
        [void]$recs.Add((New-Object PSObject -Property @{
            FileName = $fname; IsDelete = $isDel; IsRenameOld = $isRenOld; IsRenameNew = $isRenNew
            InRecycleBin = ($fname -match '(?i)^\$R'); TimeStampRaw = $ts
        }))
        if ($recs.Count -ge $Max) { break }
    }
    return $recs
}

function ConvertFrom-VssList {
    




    param([string[]]$Lines)
    $recs = New-Object System.Collections.ArrayList
    if (-not $Lines) { return $recs }
    $pendingGuid = $null; $pendingDate = $null; $pendingOrig = $null
    foreach ($ln in $Lines) {
        $mg = [regex]::Match($ln, '(\{[0-9A-Fa-f]{8}\-[0-9A-Fa-f]{4}\-[0-9A-Fa-f]{4}\-[0-9A-Fa-f]{4}\-[0-9A-Fa-f]{12}\})')
        if ($mg.Success -and $ln -notmatch 'Volume\{') { $pendingGuid = $mg.Groups[1].Value }
        $md = [regex]::Match($ln, '(\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}[ ,]+\d{1,2}:\d{2}(:\d{2})?)')
        if ($md.Success) { $pendingDate = $md.Groups[1].Value }
        $mo = [regex]::Match($ln, '(\([A-Za-z]:\)[^\r\n]*)')
        if ($mo.Success) { $pendingOrig = $mo.Groups[1].Value.Trim() }
        $mv = [regex]::Match($ln, '(HarddiskVolumeShadowCopy\d+)')
        if ($mv.Success) {
            $devFull = $null
            $mvf = [regex]::Match($ln, '(\\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy\d+)')
            if ($mvf.Success) { $devFull = $mvf.Groups[1].Value } else { $devFull = $mv.Groups[1].Value }
            [void]$recs.Add((New-Object PSObject -Property @{
                ShadowId = $pendingGuid; Device = $devFull; OriginalVolume = $pendingOrig; CreationLocal = $pendingDate
            }))
            $pendingGuid = $null
        }
    }
    return $recs
}

function Invoke-ModuleDeletedFiles {
    Write-ForensicLog -Message '--- MODULO DeletedFiles ---'
    Register-Source 'Trazabilidad de archivos eliminados ($I/$R, USN, LNK, historial PowerShell, 4660)'
    $rawDir = $script:Paths.RawDeleted
    $files  = @{}                                   
    $timeline = New-Object System.Collections.ArrayList

    
    
    
    $iCount = 0
    foreach ($drive in @(Get-CimOrWmi -ClassName 'Win32_LogicalDisk' -Filter 'DriveType=3')) {
        if ($null -eq $drive) { continue }
        $rb = Join-Path $drive.DeviceID '$Recycle.Bin'
        if (-not (Test-Path -LiteralPath $rb)) { continue }
        $sidDirs = @(Get-ChildItem -LiteralPath $rb -Force -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer })
        foreach ($sd in $sidDirs) {
            $sidName = $sd.Name
            $user = $null
            try { $user = (New-Object System.Security.Principal.SecurityIdentifier($sidName)).Translate([System.Security.Principal.NTAccount]).Value } catch { }
            $iFiles = @(Get-ChildItem -LiteralPath $sd.FullName -Force -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer -and $_.Name -like '$I*' })
            foreach ($if in $iFiles) {
                $parsed = ConvertFrom-RecycleBinIndex -Path $if.FullName
                if ($null -eq $parsed -or -not $parsed.OriginalPath) { continue }
                $iCount++
                $name = $null; try { $name = [System.IO.Path]::GetFileName($parsed.OriginalPath) } catch { $name = $parsed.OriginalPath }
                $rec = Get-DeletedFileRecord -Map $files -Path $parsed.OriginalPath -Name $name
                $rec.HasI = $true
                $rec.SID = $sidName; $rec.User = $user
                $rec.SizeBytes = $parsed.SizeBytes
                if ($parsed.DeletedUTC) { $rec.DeletedUTC = $parsed.DeletedUTC.ToString($script:TsFmt) }
                
                $rName = '$R' + $if.Name.Substring(2)
                $rPath = Join-Path $sd.FullName $rName
                $delTs = $null; if ($parsed.DeletedUTC) { $delTs = $parsed.DeletedUTC.ToString($script:TsFmt) }
                if (Test-Path -LiteralPath $rPath) {
                    $rec.HasR = $true
                    
                    try {
                        $ri = Get-Item -LiteralPath $rPath -Force -ErrorAction SilentlyContinue
                        if ($ri -and -not $ri.PSIsContainer -and $ri.Length -le $MaximumFileSizeForHashing -and $IncludeHashes) {
                            $rec.SHA256 = Get-EvidenceFileHash -Path $rPath -Algorithm SHA256
                        }
                    } catch { }
                    Add-DeletedEvidence -Record $rec -Source 'Papelera $R' -TimestampUTC $delTs -Artifact $rPath -Info 'Contenido presente en Papelera (recuperable)' -Event 'En Papelera (contenido presente)' -Confidence 'Confirmada' -Timeline $timeline
                }
                
                Add-DeletedEvidence -Record $rec -Source 'Papelera $I' -TimestampUTC $delTs -Artifact $if.FullName -Info ('Indice $I: ruta original y fecha de borrado (version {0})' -f $parsed.Version) -Event 'Enviado a Papelera' -Confidence 'Confirmada' -Timeline $timeline
            }
        }
    }
    if ($iCount -eq 0) { Register-MissingEvidence -Evidence 'Indices $I de Papelera' -Reason 'Papelera vacia/purgada o sin indices accesibles' }
    else { Write-ForensicLog -Message ('Papelera: {0} indice(s) $I parseados.' -f $iCount) }

    
    
    
    
    $profiles = @(Get-CimOrWmi -ClassName 'Win32_UserProfile' | Where-Object { $_ -and -not $_.Special -and $_.LocalPath })
    $lnkCount = 0
    foreach ($p in $profiles) {
        $recentDirs = @(
            (Join-Path $p.LocalPath 'AppData\Roaming\Microsoft\Windows\Recent'),
            (Join-Path $p.LocalPath 'Desktop'),
            (Join-Path $p.LocalPath 'AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations')
        )
        $pUser = $null; try { $pUser = (New-Object System.Security.Principal.SecurityIdentifier($p.SID)).Translate([System.Security.Principal.NTAccount]).Value } catch { }
        foreach ($rd in $recentDirs) {
            if (-not (Test-Path -LiteralPath $rd)) { continue }
            $lnks = @(Get-ChildItem -LiteralPath $rd -Filter '*.lnk' -Force -ErrorAction SilentlyContinue | Select-Object -First 2000)
            foreach ($lk in $lnks) {
                $res = Resolve-LnkTarget -LnkPath $lk.FullName
                if ($null -eq $res -or -not $res.Target) { continue }
                $target = $res.Target
                
                if ($target -notmatch '\.[A-Za-z0-9]{1,8}$') { continue }
                $present = Test-Path -LiteralPath $target
                $lnkCount++
                $name = $null; try { $name = [System.IO.Path]::GetFileName($target) } catch { $name = $target }
                $rec = Get-DeletedFileRecord -Map $files -Path $target -Name $name
                $rec.HasRef = $true
                if (-not $rec.User) { $rec.User = $pUser; $rec.SID = $p.SID }
                $lastUse = $lk.LastWriteTimeUtc.ToString($script:TsFmt)
                if ($present) {
                    
                    Add-DeletedEvidence -Record $rec -Source 'LNK (Recent)' -TimestampUTC $lastUse -Artifact $lk.FullName -Info 'Acceso directo a archivo actualmente PRESENTE (contexto de uso)' -Event 'Referencia de uso (archivo presente)' -Confidence 'Posible' -Timeline $timeline
                } else {
                    $rec.RefAbsent = $true
                    Add-DeletedEvidence -Record $rec -Source 'LNK (Recent)' -TimestampUTC $lastUse -Artifact $lk.FullName -Info 'Acceso directo cuyo destino YA NO EXISTE (posible eliminacion o movimiento)' -Event 'Referencia a archivo ausente' -Confidence 'Posible' -Timeline $timeline
                }
            }
        }
    }
    Write-ForensicLog -Message ('LNK analizados: {0} referencias a ficheros.' -f $lnkCount)

    
    
    
    $delRegex = '(?i)(Remove-Item|Remove-ItemProperty|\bdel\b|\berase\b|\brm\b|\brmdir\b|Clear-RecycleBin|\]::Delete\(|Recycle)'
    $pathRegex = '(?i)([a-z]:\\[^"''|<>*?\r\n]+\.[a-z0-9]{1,8})'
    foreach ($p in $profiles) {
        $hist = Join-Path $p.LocalPath 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
        if (-not (Test-Path -LiteralPath $hist)) { continue }
        $pUser = $null; try { $pUser = (New-Object System.Security.Principal.SecurityIdentifier($p.SID)).Translate([System.Security.Principal.NTAccount]).Value } catch { }
        $histMtime = $null; try { $histMtime = (Get-Item -LiteralPath $hist -Force).LastWriteTimeUtc.ToString($script:TsFmt) } catch { }
        $lines = @()
        try { $lines = Get-Content -LiteralPath $hist -ErrorAction SilentlyContinue -Encoding UTF8 } catch { }
        foreach ($ln in $lines) {
            if ($ln -notmatch $delRegex) { continue }
            $m = [regex]::Matches($ln, $pathRegex)
            if ($m.Count -eq 0) {
                
                continue
            }
            foreach ($mm in $m) {
                $tp = $mm.Groups[1].Value.Trim()
                $name = $null; try { $name = [System.IO.Path]::GetFileName($tp) } catch { $name = $tp }
                $rec = Get-DeletedFileRecord -Map $files -Path $tp -Name $name
                $rec.HasDeleteCmd = $true
                if (-not $rec.User) { $rec.User = $pUser; $rec.SID = $p.SID }
                Add-DeletedEvidence -Record $rec -Source 'Historial PowerShell' -TimestampUTC $histMtime -Artifact $hist -Info ('Comando de borrado (sin marca temporal por linea; cota = mtime del historial): ' + $ln.Trim()) -Event 'Comando de borrado ejecutado' -Confidence 'Probable' -Timeline $timeline
            }
        }
    }

    
    
    
    $psCsv = Join-Path $script:Paths.ParsedCSV '22_powershell_events.csv'
    if (Test-Path -LiteralPath $psCsv) {
        try {
            foreach ($row in @(Import-Csv -LiteralPath $psCsv)) {
                $txt = [string]$row.Notes
                if (-not $txt -or ($txt -notmatch $delRegex)) { continue }
                $m = [regex]::Matches($txt, $pathRegex)
                if ($m.Count -eq 0) { continue }
                foreach ($mm in $m) {
                    $tp = $mm.Groups[1].Value.Trim()
                    $name = $null; try { $name = [System.IO.Path]::GetFileName($tp) } catch { $name = $tp }
                    $rec = Get-DeletedFileRecord -Map $files -Path $tp -Name $name
                    $rec.HasDeleteCmd = $true
                    Add-DeletedEvidence -Record $rec -Source 'PowerShell 4104' -TimestampUTC $row.TimestampUTC -Artifact 'Microsoft-Windows-PowerShell/Operational' -Info 'Bloque de script con operacion de borrado (con marca temporal)' -Event 'Comando de borrado (PowerShell 4104)' -Confidence 'Alta' -Timeline $timeline
                }
            }
        } catch { Write-ForensicLog -Level DEBUG -Message ('No se pudo correlacionar 4104: {0}' -f $_.Exception.Message) }
    }
    $secCsv = Join-Path $script:Paths.ParsedCSV '20_security_events.csv'
    if (Test-Path -LiteralPath $secCsv) {
        try {
            foreach ($row in @(Import-Csv -LiteralPath $secCsv | Where-Object { $_.EventId -eq '4660' -or $_.EventId -eq '4663' })) {
                $info = [string]$row.Notes
                $tp = $null
                $m = [regex]::Match($info, $pathRegex)
                if ($m.Success) { $tp = $m.Groups[1].Value.Trim() }
                $name = $null; if ($tp) { try { $name = [System.IO.Path]::GetFileName($tp) } catch { $name = $tp } }
                if (-not $tp -and -not $name) { $name = '(objeto sin ruta en el evento)' }
                $rec = Get-DeletedFileRecord -Map $files -Path $tp -Name $name
                if ($row.EventId -eq '4660') { $rec.Has4660 = $true }
                if (-not $rec.User) { $rec.User = $row.User; $rec.SID = $row.UserSID }
                $ev = $(if ($row.EventId -eq '4660') { 'Objeto eliminado (auditoria 4660)' } else { 'Acceso con intencion de borrado (4663)' })
                Add-DeletedEvidence -Record $rec -Source ('Security ' + $row.EventId) -TimestampUTC $row.TimestampUTC -Artifact 'Security.evtx' -Info 'Auditoria de acceso a objetos (requiere SACL activa)' -Event $ev -Confidence 'Alta' -Timeline $timeline
            }
        } catch { Write-ForensicLog -Level DEBUG -Message ('No se pudo correlacionar 4660/4663: {0}' -f $_.Exception.Message) }
    } else {
        Register-MissingEvidence -Evidence 'Eventos 4660/4663 (borrado auditado)' -Reason 'Security.evtx no disponible o auditoria de acceso a objetos desactivada (lo habitual)'
    }

    
    
    
    
    
    
    
    $usnParsed = 0; $usnEmptied = 0; $usnDirect = 0; $usnToBin = 0
    if ($script:IsAdmin) {
        $vol = (Get-WinEnvPath SystemDrive)
        $readerOk = Initialize-UsnReader
        $q = $null
        if ($readerOk) { try { $q = [ForensicUsn]::QueryJournal($vol) } catch { $q = $null } }

        if (-not $readerOk) {
            Write-ForensicLog -Level WARN -Message 'USN: no se pudo compilar el lector API (posible modo de lenguaje restringido). Se intentara preservar el journal via fsutil.'
            Register-MissingEvidence -Evidence 'USN Journal (lector API)' -Reason 'No se pudo compilar el lector en memoria (modo de lenguaje restringido). Respaldo: fsutil; reconstruccion completa offline ($UsnJrnl:$J).'
        }
        elseif ($null -eq $q) {
            Write-ForensicLog -Level WARN -Message ('USN: NO se pudo abrir el volumen \\.\{0} ni consultar el journal via API. Causa probable: bloqueo de seguridad (AV/EDR) del acceso directo al volumen (el mismo que impidio SAM/SECURITY), o journal desactivado. Se preservara via fsutil.' -f $vol)
            Register-MissingEvidence -Evidence 'USN Journal (apertura de volumen)' -Reason ('No se pudo abrir \\.\{0} via API: probable bloqueo AV/EDR del acceso raw al volumen, o journal desactivado. Verificar con "fsutil usn queryjournal {0}". Reconstruccion offline: $UsnJrnl:$J.' -f $vol)
        }
        else {
            Write-ForensicLog -Message ('USN: journal accesible (JournalID={0}, LowestValidUsn={1}, NextUsn={2}). Leyendo borrados desde {3}...' -f $q[0], $q[3], $q[2], $StartDate.ToString('yyyy-MM-dd'))
            $usnRecs = $null
            try { $usnRecs = Get-UsnDeletionRecords -Volume $vol -SinceUtc ($StartDate.ToUniversalTime()) -Max 30000 -MaxIter 400000 }
            catch { Write-ForensicLog -Level WARN -Message ('USN: error leyendo registros: {0}' -f $_.Exception.Message) }

            if ($null -eq $usnRecs -or $usnRecs.Count -eq 0) {
                Write-ForensicLog -Level WARN -Message 'USN: 0 registros de borrado/movimiento en la ventana analizada. Posibles causas: (a) no hay borrados recientes en el rango de fechas; (b) el journal roto y perdio los mas antiguos; (c) filtro de fechas. Amplie el rango con -StartDate si busca borrados anteriores. Se preserva el journal via fsutil.'
            } else {
                $cover = ('JournalID={0} LowestValidUsn={1} NextUsn={2}' -f $q[0], $q[3], $q[2])
                $minTs = $null
                foreach ($rr in $usnRecs) { if ($rr.TimeStampUTC -and (($null -eq $minTs) -or ($rr.TimeStampUTC -lt $minTs))) { $minTs = $rr.TimeStampUTC } }

                
                $usnFlat = @($usnRecs | ForEach-Object {
                    $rlist = New-Object System.Collections.ArrayList
                    if (($_.Reason -band 0x200) -ne 0)  { [void]$rlist.Add('FILE_DELETE') }
                    if (($_.Reason -band 0x1000) -ne 0) { [void]$rlist.Add('RENAME_OLD') }
                    if (($_.Reason -band 0x2000) -ne 0) { [void]$rlist.Add('RENAME_NEW') }
                    New-Object PSObject -Property @{
                        Usn = $_.Usn; Frn = $_.Frn; ParentFrn = $_.ParentFrn
                        ReasonHex = ('0x{0:x8}' -f $_.Reason); Reasons = ($rlist -join '+')
                        TimeStampUTC = $(if ($_.TimeStampUTC) { $_.TimeStampUTC.ToString($script:TsFmt) } else { $null })
                        FileName = $_.FileName
                    }
                })
                if ($usnFlat.Count -gt 0) { Export-ObjectData -Data $usnFlat -BaseName '97_usn_deletions' -Category 'DeletedFiles' }

                
                $byFrn = @{}
                foreach ($r in $usnRecs) {
                    if (-not $byFrn.ContainsKey($r.Frn)) { $byFrn[$r.Frn] = New-Object System.Collections.ArrayList }
                    [void]$byFrn[$r.Frn].Add($r)
                }
                foreach ($frn in $byFrn.Keys) {
                    $group = @($byFrn[$frn] | Sort-Object Usn)
                    $renOld = $null; $renNew = $null; $del = $null
                    foreach ($g in $group) {
                        if (($g.Reason -band 0x1000) -ne 0 -and $null -eq $renOld) { $renOld = $g }
                        if (($g.Reason -band 0x2000) -ne 0) { $renNew = $g }
                        if (($g.Reason -band 0x200)  -ne 0) { $del = $g }
                    }
                    $srcRec = $(if ($renOld) { $renOld } elseif ($del) { $del } else { $renNew })
                    if ($null -eq $srcRec) { continue }
                    $name = $srcRec.FileName
                    if (-not $name) { continue }
                    $parentPath = Resolve-UsnParentPath -Volume $vol -ParentFrn $srcRec.ParentFrn
                    $fullPath = $null
                    if ($parentPath) { $fullPath = ($parentPath.TrimEnd('\') + '\' + $name) }

                    $toBin = $false
                    if ($renNew) {
                        $np = Resolve-UsnParentPath -Volume $vol -ParentFrn $renNew.ParentFrn
                        if (($np -and ($np -match '(?i)\$Recycle\.Bin')) -or ($renNew.FileName -match '(?i)^\$R')) { $toBin = $true }
                    }
                    $delInBin = $false
                    if ($del) {
                        $dp = Resolve-UsnParentPath -Volume $vol -ParentFrn $del.ParentFrn
                        if (($dp -and ($dp -match '(?i)\$Recycle\.Bin')) -or ($del.FileName -match '(?i)^\$R')) { $delInBin = $true }
                    }

                    $rec = Get-DeletedFileRecord -Map $files -Path $fullPath -Name $name
                    $usnParsed++
                    $moveTs = $(if ($renNew -and $renNew.TimeStampUTC) { $renNew.TimeStampUTC.ToString($script:TsFmt) } else { $null })
                    $delTs  = $(if ($del -and $del.TimeStampUTC) { $del.TimeStampUTC.ToString($script:TsFmt) } else { $null })

                    if ($del -and ($toBin -or $delInBin)) {
                        $rec.HasUsnEmptied = $true; $usnEmptied++
                        if ($delTs) { $rec.DeletedUTC = $delTs }
                        if ($moveTs) {
                            Add-DeletedEvidence -Record $rec -Source 'USN Journal' -TimestampUTC $moveTs -Artifact ('USN rename->$Recycle.Bin (FRN {0})' -f $frn) -Info 'Archivo movido a la Papelera (registro RENAME del USN)' -Event 'Movido a Papelera' -Confidence 'Alta' -Timeline $timeline
                        }
                        Add-DeletedEvidence -Record $rec -Source 'USN Journal' -TimestampUTC $delTs -Artifact ('USN FILE_DELETE (FRN {0})' -f $frn) -Info 'Eliminado definitivamente de la Papelera (registro FILE_DELETE del USN)' -Event 'Eliminado de la Papelera (vaciado)' -Confidence 'Alta' -Timeline $timeline
                    } elseif ($del) {
                        $rec.HasUsnDirect = $true; $usnDirect++
                        if ($delTs) { $rec.DeletedUTC = $delTs }
                        Add-DeletedEvidence -Record $rec -Source 'USN Journal' -TimestampUTC $delTs -Artifact ('USN FILE_DELETE (FRN {0})' -f $frn) -Info 'Eliminado directamente (sin pasar por Papelera): Shift+Supr, API o aplicacion' -Event 'Eliminado directamente (USN)' -Confidence 'Alta' -Timeline $timeline
                    } elseif ($toBin) {
                        $rec.HasUsnToBin = $true; $usnToBin++
                        if ($moveTs) { $rec.DeletedUTC = $moveTs }
                        Add-DeletedEvidence -Record $rec -Source 'USN Journal' -TimestampUTC $moveTs -Artifact ('USN rename->$Recycle.Bin (FRN {0})' -f $frn) -Info 'Movido a la Papelera (sin registro posterior de vaciado en el journal)' -Event 'Movido a Papelera' -Confidence 'Alta' -Timeline $timeline
                    }
                    if (-not $fullPath) {
                        $rec.Notes = 'Ruta original no resoluble en vivo (directorio padre eliminado); reconstruir con $MFT offline.'
                    }
                }
                Write-ForensicLog -Message ('USN: {0} registros brutos; reconstruidos {1} archivos -> vaciados de Papelera: {2}, borrados directos (Shift+Supr/app): {3}, movidos a Papelera: {4}.' -f $usnRecs.Count, $usnParsed, $usnEmptied, $usnDirect, $usnToBin)
                if ($minTs) { Write-ForensicLog -Message ('USN: evento mas antiguo conservado ~ {0} UTC ({1}). Los borrados anteriores a esa fecha pudieron perderse por rotacion del journal.' -f $minTs.ToString($script:TsFmt), $cover) }
            }
        }

        
        
        if (Test-CommandAvailable 'fsutil.exe') {
            $usnRaw = Join-Path $rawDir 'usn_readjournal_partial.txt'
            try {
                $raw = & $env:ComSpec /c ('fsutil usn readjournal {0} 2>&1' -f $vol) 2>$null | Select-Object -First 400000
                if ($raw -and (@($raw).Count -gt 3)) {
                    [System.IO.File]::WriteAllLines($usnRaw, [string[]]$raw, (New-Object System.Text.UTF8Encoding($false)))
                    Register-Evidence -Path $usnRaw -Category 'DeletedFiles' -SourceDescription ('fsutil usn readjournal ' + $vol) -Notes 'Volcado parcial del USN Journal (respaldo para analisis offline). La reconstruccion estructurada en vivo esta en 97_usn_deletions.csv si la API funciono.'
                    Write-ForensicLog -Message 'USN: journal preservado (parcial) via fsutil para analisis offline.'
                    
                    if ($usnParsed -eq 0) {
                        $fsRecs = ConvertFrom-FsutilUsnText -Lines ([string[]]$raw) -Max 8000
                        $fsEmptied = 0; $fsDirect = 0; $fsToBin = 0
                        foreach ($fr in $fsRecs) {
                            $nm = $fr.FileName
                            $rec = Get-DeletedFileRecord -Map $files -Path $null -Name $nm
                            $tsU = $null
                            if ($fr.TimeStampRaw) { try { $tsU = ([datetime]$fr.TimeStampRaw).ToUniversalTime().ToString($script:TsFmt) } catch { } }
                            if ($fr.IsDelete -and $fr.InRecycleBin) {
                                $rec.HasUsnEmptied = $true; $fsEmptied++
                                if ($tsU) { $rec.DeletedUTC = $tsU }
                                Add-DeletedEvidence -Record $rec -Source 'USN (fsutil, texto)' -TimestampUTC $tsU -Artifact 'fsutil usn readjournal' -Info 'FILE_DELETE de un $R (vaciado de Papelera). Ruta original no disponible por esta via.' -Event 'Eliminado de la Papelera (vaciado)' -Confidence 'Probable' -Timeline $timeline
                            } elseif ($fr.IsDelete) {
                                $rec.HasUsnDirect = $true; $fsDirect++
                                if ($tsU) { $rec.DeletedUTC = $tsU }
                                Add-DeletedEvidence -Record $rec -Source 'USN (fsutil, texto)' -TimestampUTC $tsU -Artifact 'fsutil usn readjournal' -Info 'FILE_DELETE directo (Shift+Supr/app). Ruta original no disponible por esta via.' -Event 'Eliminado directamente (USN)' -Confidence 'Probable' -Timeline $timeline
                            } elseif ($fr.IsRenameNew -and $fr.InRecycleBin) {
                                $rec.HasUsnToBin = $true; $fsToBin++
                                if ($tsU) { $rec.DeletedUTC = $tsU }
                                Add-DeletedEvidence -Record $rec -Source 'USN (fsutil, texto)' -TimestampUTC $tsU -Artifact 'fsutil usn readjournal' -Info 'Renombrado hacia $Recycle.Bin (movido a Papelera).' -Event 'Movido a Papelera' -Confidence 'Probable' -Timeline $timeline
                            }
                        }
                        Write-ForensicLog -Message ('USN (fsutil texto): reconstruidos -> vaciados: {0}, directos: {1}, a Papelera: {2}. Confianza Probable (sin ruta original; usar API o imagen para confirmar).' -f $fsEmptied, $fsDirect, $fsToBin)
                    }
                } else {
                    Register-MissingEvidence -Evidence 'USN Journal (fsutil readjournal)' -Reason 'fsutil no devolvio registros (journal deshabilitado, vacio o acceso bloqueado). Habilitar/consultar con "fsutil usn queryjournal" o reconstruir offline.'
                }
            } catch {
                Register-MissingEvidence -Evidence 'USN Journal (fsutil readjournal)' -Reason ('fsutil fallo: {0}. Reconstruir offline desde $UsnJrnl:$J.' -f $_.Exception.Message)
            }
        }
    } else {
        Register-MissingEvidence -Evidence 'USN Journal (borrados definitivos)' -Reason 'Requiere administrador para abrir el volumen. Sin el USN no pueden detectarse en vivo los archivos vaciados de la Papelera ni los Shift+Supr; reconstruir desde imagen/offline ($UsnJrnl:$J, $MFT).'
    }
    
    Register-MissingEvidence -Evidence '$MFT / $LogFile / contenido completo $UsnJrnl' -Reason 'Metadatos NTFS de bajo nivel: requieren imagen forense o acceso raw. El USN en vivo cubre la ventana no rotada; la recuperacion de contenido de archivos vaciados se realiza offline (MFTECmd, plaso, VSS montado).'
    
    
    
    $records = New-Object System.Collections.ArrayList
    foreach ($k in $files.Keys) {
        $r = $files[$k]
        $srcSet = @($r.Evidence | ForEach-Object { $_.Source } | Select-Object -Unique)
        $evCount = $r.Evidence.Count

        
        if ((-not $r.HasI) -and (-not $r.HasDeleteCmd) -and (-not $r.Has4660) -and (-not $r.RefAbsent) -and (-not $r.HasUsnEmptied) -and (-not $r.HasUsnDirect) -and (-not $r.HasUsnToBin)) {
            continue
        }

        
        if ($r.HasR) { $r.Status = 'En Papelera'; $r.Recoverability = 'Recuperable' }
        elseif ($r.HasUsnEmptied) { $r.Status = 'Eliminado de la Papelera (vaciado)'; $r.Recoverability = 'No recuperable en vivo (VSS/imagen offline)' }
        elseif ($r.HasI) { $r.Status = 'Eliminado de la Papelera'; $r.Recoverability = 'Indeterminada (indice $I sin $R)' }
        elseif ($r.HasUsnDirect) { $r.Status = 'Eliminado directamente (Shift+Supr/app)'; $r.Recoverability = 'No recuperable en vivo (VSS/imagen offline)' }
        elseif ($r.Has4660) { $r.Status = 'Eliminado directamente'; $r.Recoverability = 'Indeterminada' }
        elseif ($r.HasDeleteCmd) { $r.Status = 'Eliminado directamente (por comando)'; $r.Recoverability = 'Indeterminada' }
        elseif ($r.HasUsnToBin) { $r.Status = 'Movido a Papelera'; $r.Recoverability = 'Posiblemente recuperable (ver Papelera)' }
        elseif ($r.RefAbsent) { $r.Status = 'Referenciado pero ausente'; $r.Recoverability = 'Indeterminada' }
        else { $r.Status = 'Indeterminado'; $r.Recoverability = 'Indeterminada' }

        
        if ($r.HasUsnEmptied) { $r.DeletionMethod = 'Vaciado de la Papelera (RENAME+FILE_DELETE en USN)' }
        elseif ($r.HasUsnDirect) { $r.DeletionMethod = 'Borrado directo Shift+Supr/API (FILE_DELETE en USN)' }
        elseif ($r.HasI -or $r.HasR) { $r.DeletionMethod = 'Envio a Papelera de reciclaje' }
        elseif ($r.HasUsnToBin) { $r.DeletionMethod = 'Movido a Papelera (RENAME en USN)' }
        elseif ($r.HasDeleteCmd) { $r.DeletionMethod = 'Comando/script de borrado (posible Shift+Supr o API)' }
        elseif ($r.Has4660) { $r.DeletionMethod = 'Operacion de borrado (auditada por SACL)' }
        else { $r.DeletionMethod = 'Desconocido (solo referencia de existencia)' }

        
        $independent = @($srcSet).Count
        $pathResolved = [bool]$r.OriginalPath
        if ($r.HasI -or $r.HasR) { $r.Confidence = 'Confirmada' }
        elseif (($r.HasUsnEmptied -or $r.HasUsnDirect) -and $pathResolved) { $r.Confidence = 'Alta' }
        elseif ($r.HasUsnEmptied -or $r.HasUsnDirect) { $r.Confidence = 'Probable' }
        elseif ($r.HasUsnToBin) { $r.Confidence = 'Alta' }
        elseif ($r.Has4660 -and $independent -ge 1) { $r.Confidence = 'Alta' }
        elseif ($r.HasDeleteCmd -and $independent -ge 2) { $r.Confidence = 'Alta' }
        elseif ($r.HasDeleteCmd) { $r.Confidence = 'Probable' }
        elseif ($r.RefAbsent -and $independent -ge 2) { $r.Confidence = 'Probable' }
        elseif ($r.RefAbsent) { $r.Confidence = 'Posible' }
        else { $r.Confidence = 'Indeterminada' }

        $r.Notes = ('Evidencias: {0} | Fuentes: {1}' -f $evCount, ($srcSet -join ', '))

        
        [void]$records.Add((New-Object PSObject -Property @{
            Name = $r.Name; Extension = $r.Extension; Type = $r.Type
            OriginalPath = $r.OriginalPath; Directory = $r.Directory; Volume = $r.Volume
            SizeBytes = $r.SizeBytes; User = $r.User; SID = $r.SID
            CreatedUTC = $r.CreatedUTC; ModifiedUTC = $r.ModifiedUTC; LastAccessUTC = $r.LastAccessUTC
            DeletedUTC = $r.DeletedUTC; DeletionMethod = $r.DeletionMethod
            Status = $r.Status; Recoverability = $r.Recoverability; SHA256 = $r.SHA256
            Confidence = $r.Confidence; EvidenceCount = $evCount; Sources = ($srcSet -join '; '); Notes = $r.Notes
        }))
    }

    
    
    
    if ($records.Count -gt 0) {
        Export-ObjectData -Data $records -BaseName '95_deleted_files' -Category 'DeletedFiles'
        
        $detailed = @($files.Values | Where-Object {
            $_.HasI -or $_.HasDeleteCmd -or $_.Has4660 -or $_.RefAbsent -or $_.HasUsnEmptied -or $_.HasUsnDirect -or $_.HasUsnToBin
        } | ForEach-Object {
            New-Object PSObject -Property @{
                Archivo = New-Object PSObject -Property @{
                    Nombre = $_.Name; Extension = $_.Extension; Tipo = $_.Type
                    Ruta_original = $_.OriginalPath; Volumen = $_.Volume; Tamano = $_.SizeBytes
                    Usuario = $_.User; SID = $_.SID
                    Creacion = $_.CreatedUTC; Modificacion = $_.ModifiedUTC; Ultimo_acceso = $_.LastAccessUTC
                    Eliminacion = $_.DeletedUTC; Metodo_eliminacion = $_.DeletionMethod
                    Estado = $_.Status; Hash = $_.SHA256; Recuperabilidad = $_.Recoverability
                    Confianza = $_.Confidence
                }
                Evidencias = @($_.Evidence | ForEach-Object {
                    New-Object PSObject -Property @{ Fuente = $_.Source; Timestamp = $_.TimestampUTC; Artefacto = $_.Artifact; Informacion = $_.Info; Confianza = $_.Confidence }
                })
            }
        })
        try {
            $jsonPath = Join-Path $script:Paths.ParsedJSON '95_deleted_files_detailed.json'
            [System.IO.File]::WriteAllText($jsonPath, ($detailed | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
            Register-Evidence -Path $jsonPath -Category 'DeletedFiles' -SourceDescription 'Registros consolidados con evidencias anidadas'
        } catch { Write-ForensicLog -Level ERROR -Message ('Error exportando JSON detallado de borrados: {0}' -f $_.Exception.Message) }
        Write-ForensicLog -Message ('DeletedFiles: {0} archivo(s) con evidencia de eliminacion consolidados.' -f $records.Count)
    } else {
        Register-MissingEvidence -Evidence 'Archivos eliminados (consolidado)' -Reason 'No se hallo evidencia de eliminacion en las fuentes disponibles en vivo'
    }

    if ($timeline.Count -gt 0) {
        $tl = @($timeline | Sort-Object -Property TimestampUTC)
        $tlCsv = Join-Path $script:Paths.ParsedCSV '96_deleted_files_timeline.csv'
        try {
            $tl | Export-Csv -LiteralPath $tlCsv -NoTypeInformation -Encoding UTF8
            Register-Evidence -Path $tlCsv -Category 'DeletedFiles' -SourceDescription 'Cronologia de eventos de archivos eliminados'
        } catch { Write-ForensicLog -Level ERROR -Message ('Error exportando timeline de borrados: {0}' -f $_.Exception.Message) }
    }

    
    
    
    
    if ($script:IsAdmin -and (Test-CommandAvailable 'vssadmin.exe')) {
        $vssTxt = Join-Path $script:Paths.ParsedTXT 'vss_shadows.txt'
        $vssRaw = $null
        if (Test-Path -LiteralPath $vssTxt) { try { $vssRaw = Get-Content -LiteralPath $vssTxt -ErrorAction SilentlyContinue } catch { } }
        if (-not $vssRaw) { try { $vssRaw = & $env:ComSpec /c 'vssadmin list shadows 2>&1' } catch { } }
        if ($vssRaw) {
            $vssRecs = ConvertFrom-VssList -Lines ([string[]]$vssRaw)
            
            $wmiShadows = @(Get-CimOrWmi -ClassName 'Win32_ShadowCopy')
            if ($wmiShadows.Count -gt 0) {
                $shadowById = @{}
                foreach ($sh in $wmiShadows) { if ($sh -and $sh.ID) { $shadowById[$sh.ID] = $sh } }
                foreach ($vr in $vssRecs) {
                    $sh = $shadowById[$vr.ShadowId]
                    if ($sh) {
                        $vr | Add-Member -NotePropertyName 'State' -NotePropertyValue $sh.State -Force
                        $vr | Add-Member -NotePropertyName 'ClientAccessible' -NotePropertyValue $sh.ClientAccessible -Force
                        $vr | Add-Member -NotePropertyName 'Persistent' -NotePropertyValue $sh.Persistent -Force
                        $vr | Add-Member -NotePropertyName 'OriginatingMachine' -NotePropertyValue $sh.OriginatingMachine -Force
                        $vr | Add-Member -NotePropertyName 'ServiceMachine' -NotePropertyValue $sh.ServiceMachine -Force
                    }
                }
            }
            if ($vssRecs.Count -gt 0) {
                Export-ObjectData -Data $vssRecs -BaseName '98_vss_snapshots' -Category 'DeletedFiles'
                Write-ForensicLog -Message ('VSS: {0} instantanea(s) de volumen catalogadas (posibles puntos de recuperacion offline).' -f $vssRecs.Count)
            } else {
                Register-MissingEvidence -Evidence 'Instantaneas VSS' -Reason 'No hay instantaneas de volumen (o no se pudieron catalogar). Sin VSS, los hechos anteriores a la ventana del USN/Security requieren imagen de disco.'
            }
        }
    } else {
        Register-MissingEvidence -Evidence 'Instantaneas VSS' -Reason 'Requiere administrador (vssadmin). Las instantaneas pueden contener el estado del disco de semanas atras, incluidos archivos ya borrados.'
    }

    Write-ForensicLog -Message 'Modulo DeletedFiles completado. Reconstruccion exhaustiva de contenido/timeline NTFS ($MFT/$UsnJrnl) requiere imagen forense o analisis offline.'
}











function Get-EventDataHash {
    
    param($Event)
    $h = @{}
    try {
        $xml = [xml]$Event.ToXml()
        if ($xml.Event.EventData -and $xml.Event.EventData.Data) {
            foreach ($d in @($xml.Event.EventData.Data)) {
                if ($d -is [string]) { continue }
                if ($d.Name) { $h[$d.Name] = $d.'#text' }
            }
        }
        
        
        if ($xml.Event.UserData) {
            foreach ($container in @($xml.Event.UserData.ChildNodes)) {
                if ($null -eq $container -or -not $container.ChildNodes) { continue }
                foreach ($n in @($container.ChildNodes)) {
                    if ($null -eq $n -or -not $n.Name -or $n.Name -eq '#text') { continue }
                    if (-not $h.ContainsKey($n.Name)) { $h[$n.Name] = $n.InnerText }
                }
            }
        }
    } catch { }
    return $h
}

function Resolve-SessionIp {
    
    param([hashtable]$Map, [string]$User, [datetime]$WhenUtc)
    if (-not $User -or -not $Map.ContainsKey($User)) { return $null }
    $best = $null; $bestT = $null
    foreach ($e in $Map[$User]) {
        if ($e.T -le $WhenUtc -and (($null -eq $bestT) -or ($e.T -gt $bestT))) { $bestT = $e.T; $best = $e.IP }
    }
    return $best
}

function Protect-CredentialInCommand {
    



    param([string]$Command)
    if (-not $Command) { return $Command }
    $c = $Command
    
    $c = [regex]::Replace($c, '(?i)(\bnet1?\s+user\s+[^\s/]+\s+)(?!/)("[^"]*"|[^\s/]+)', '${1}[CONTRASENA_REDACTADA]')
    
    $c = [regex]::Replace($c, '(?i)(ConvertTo-SecureString\s+)("[^"]*"|''[^'']*''|\S+)', '${1}[CONTRASENA_REDACTADA]')
    $c = [regex]::Replace($c, '(?i)(-(?:Account|New)?Password\s+)("[^"]*"|''[^'']*''|\$\w+|\S+)', '${1}[CONTRASENA_REDACTADA]')
    $c = [regex]::Replace($c, '(?i)(-AsPlainText\s+-Force)', '${1}')
    return $c
}














function Convert-Rot13 {
    param([string]$Text)
    if (-not $Text) { return $Text }
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $Text.ToCharArray()) {
        $c = [int][char]$ch
        if ($c -ge 65 -and $c -le 90) { $c = ((($c - 65 + 13) % 26) + 65) }
        elseif ($c -ge 97 -and $c -le 122) { $c = ((($c - 97 + 13) % 26) + 97) }
        [void]$sb.Append([char]$c)
    }
    return $sb.ToString()
}

function Get-Utf16FromBytes {
    
    param([byte[]]$Bytes, [int]$Start = 0)
    if ($null -eq $Bytes) { return '' }
    $sb = New-Object System.Text.StringBuilder
    for ($i = $Start; $i + 1 -lt $Bytes.Length; $i += 2) {
        $code = $Bytes[$i] + ($Bytes[$i + 1] * 256)
        if ($code -eq 0) { break }
        [void]$sb.Append([char]$code)
    }
    return $sb.ToString()
}

function Get-Utf16Runs {
    
    param([byte[]]$Bytes, [int]$Min = 3)
    $res = New-Object System.Collections.ArrayList
    if ($null -eq $Bytes) { return $res }
    $cur = New-Object System.Text.StringBuilder
    for ($i = 0; $i + 1 -lt $Bytes.Length; $i += 2) {
        $code = $Bytes[$i] + ($Bytes[$i + 1] * 256)
        if ($code -ge 32 -and $code -lt 0xD800 -and $code -ne 0x7F) { [void]$cur.Append([char]$code) }
        else { if ($cur.Length -ge $Min) { [void]$res.Add($cur.ToString()) }; $cur = New-Object System.Text.StringBuilder }
    }
    if ($cur.Length -ge $Min) { [void]$res.Add($cur.ToString()) }
    return $res
}

function Get-RegKeySafe {
    param([string]$Path)
    try { if (Test-Path -LiteralPath $Path) { return Get-Item -LiteralPath $Path -ErrorAction Stop } } catch { }
    return $null
}

function Get-RegKeyLastWriteUtc {
    




    param($RegKeyItem)
    if ($null -eq $RegKeyItem) { return $null }
    try {
        
        $rk = $RegKeyItem
        if ($rk.PSObject.Properties['Handle']) { $rk = $RegKeyItem }
        
        
        
        $lwt = $null
        try { $lwt = $RegKeyItem.LastWriteTime } catch { }
        if (-not $lwt -and $RegKeyItem.PSObject.Properties['PSChildName']) {
            
            return $null
        }
        if ($lwt) { return ([datetime]$lwt).ToUniversalTime() }
    } catch { }
    return $null
}

function Get-MruListExOrder {
    
    param($RegKeyItem)
    $order = New-Object System.Collections.ArrayList
    if ($null -eq $RegKeyItem) { return $order }
    try {
        $raw = [byte[]]$RegKeyItem.GetValue('MRUListEx')
        if ($raw) {
            for ($i = 0; ($i + 4) -le $raw.Length; $i += 4) {
                $slot = [BitConverter]::ToInt32($raw, $i)
                if ($slot -eq -1) { break }
                [void]$order.Add($slot)
            }
        }
    } catch { }
    return $order
}

function Invoke-ModuleUserActivity {
    Write-ForensicLog -Message '--- MODULO UserActivity ---'
    Register-Source 'Actividad de usuario (UserAssist, RecentDocs, RunMRU, TypedPaths, WordWheelQuery, TypedURLs, ShellBags)'

    
    $sids = @()
    try {
        $sids = @(Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction Stop |
            Where-Object { $_.PSChildName -match '^S-1-5-21-' -and $_.PSChildName -notmatch '_Classes$' } |
            ForEach-Object { $_.PSChildName })
    } catch {
        Write-ForensicLog -Level WARN -Message ('UserActivity: no se pudo enumerar HKEY_USERS: {0}' -f $_.Exception.Message)
    }
    if ($sids.Count -eq 0) {
        Register-MissingEvidence -Evidence 'Artefactos de actividad de usuario (HKU)' -Reason 'No hay hives de usuario cargadas (ningun usuario con sesion activa) o sin acceso. Los NTUSER.DAT/UsrClass.dat de perfiles no cargados se analizan offline (ya preservados en evidencia).'
        Write-ForensicLog -Message 'UserActivity: sin hives HKU cargadas; nada que extraer en vivo.'
        return
    }
    Write-ForensicLog -Message ('UserActivity: {0} hive(s) de usuario cargadas.' -f $sids.Count)

    $uaRecs = New-Object System.Collections.ArrayList   
    $rdRecs = New-Object System.Collections.ArrayList   
    $runRecs = New-Object System.Collections.ArrayList  
    $tpRecs = New-Object System.Collections.ArrayList   
    $wwRecs = New-Object System.Collections.ArrayList   
    $urlRecs = New-Object System.Collections.ArrayList  
    $sbRecs = New-Object System.Collections.ArrayList   
    $timeline = New-Object System.Collections.ArrayList

    foreach ($sid in $sids) {
        $acct = $sid
        try { $acct = (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value } catch { }
        $root = "Registry::HKEY_USERS\$sid"

        
        $guids = @('{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}', '{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}')
        foreach ($g in $guids) {
            $k = Get-RegKeySafe ("$root\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\$g\Count")
            if ($null -eq $k) { continue }
            foreach ($vn in $k.GetValueNames()) {
                if (-not $vn) { continue }
                $prog = Convert-Rot13 $vn
                if ($prog -like 'UEME_*') { continue }
                $data = $null; try { $data = [byte[]]$k.GetValue($vn) } catch { }
                $count = $null; $lastRun = $null
                if ($data -and $data.Length -ge 68) {
                    try { $count = [BitConverter]::ToInt32($data, 4) } catch { }
                    try { $ft = [BitConverter]::ToInt64($data, 60); if ($ft -gt 0) { $lastRun = [DateTime]::FromFileTimeUtc($ft).ToString($script:TsFmt) } } catch { }
                }
                [void]$uaRecs.Add((New-Object PSObject -Property @{
                    User = $acct; SID = $sid; Program = $prog; RunCount = $count; LastRunUTC = $lastRun
                }))
                if ($lastRun) {
                    [void]$timeline.Add((New-Object PSObject -Property @{
                        TimestampUTC = $lastRun; User = $acct; Event = 'Ejecucion de programa (UserAssist)'; Item = $prog; Source = 'UserAssist'; Confidence = 'Alta'
                    }))
                }
            }
        }

        
        $rdRoot = Get-RegKeySafe ("$root\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs")
        if ($rdRoot) {
            $rdKeys = New-Object System.Collections.ArrayList
            [void]$rdKeys.Add($rdRoot)
            try { foreach ($sk in $rdRoot.GetSubKeyNames()) { $kk = Get-RegKeySafe ("$root\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\$sk"); if ($kk) { [void]$rdKeys.Add($kk) } } } catch { }
            foreach ($rk in $rdKeys) {
                $ext = $rk.PSChildName; if ($ext -eq 'RecentDocs') { $ext = '(todas)' }
                
                
                $keyLwt = Get-RegKeyLastWriteUtc $rk
                $mruOrder = Get-MruListExOrder $rk
                $mostRecentSlot = $(if ($mruOrder.Count -gt 0) { [string]$mruOrder[0] } else { $null })
                foreach ($vn in $rk.GetValueNames()) {
                    if ($vn -notmatch '^\d+$') { continue }
                    $data = $null; try { $data = [byte[]]$rk.GetValue($vn) } catch { }
                    if (-not $data) { continue }
                    $fname = Get-Utf16FromBytes -Bytes $data -Start 0
                    if ($fname -and $fname.Length -ge 1) {
                        $tsUtc = $null; $tsSrc = 'Sin fecha por entrada'; $tsConf = 'Ninguna'
                        if ($mostRecentSlot -and $vn -eq $mostRecentSlot -and $keyLwt) {
                            $tsUtc = $keyLwt.ToString($script:TsFmt); $tsSrc = 'LastWrite de la clave (entrada mas reciente)'; $tsConf = 'Aproximada'
                        }
                        [void]$rdRecs.Add((New-Object PSObject -Property @{
                            User = $acct; SID = $sid; Extension = $ext; FileName = $fname
                            TimestampUTC = $tsUtc; TimestampSource = $tsSrc; TimestampConfidence = $tsConf
                        }))
                    }
                }
            }
        }

        
        $runK = Get-RegKeySafe ("$root\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU")
        if ($runK) {
            $runLwt = Get-RegKeyLastWriteUtc $runK
            $runMru = $null; try { $runMru = [string]$runK.GetValue('MRUList') } catch { }
            $runMostRecent = $(if ($runMru -and $runMru.Length -gt 0) { $runMru.Substring(0,1) } else { $null })
            foreach ($vn in $runK.GetValueNames()) {
                if ($vn -eq 'MRUList') { continue }
                $val = $null; try { $val = [string]$runK.GetValue($vn) } catch { }
                if ($val) {
                    $val = ($val -replace "\x01$", '')
                    $tsUtc = $null; $tsConf = 'Ninguna'
                    if ($runMostRecent -and $vn -eq $runMostRecent -and $runLwt) { $tsUtc = $runLwt.ToString($script:TsFmt); $tsConf = 'Aproximada' }
                    [void]$runRecs.Add((New-Object PSObject -Property @{ User = $acct; SID = $sid; Slot = $vn; Command = $val; TimestampUTC = $tsUtc; TimestampConfidence = $tsConf }))
                }
            }
        }

        
        $tpK = Get-RegKeySafe ("$root\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths")
        if ($tpK) {
            foreach ($vn in $tpK.GetValueNames()) {
                $val = $null; try { $val = [string]$tpK.GetValue($vn) } catch { }
                if ($val) { [void]$tpRecs.Add((New-Object PSObject -Property @{ User = $acct; SID = $sid; Slot = $vn; Path = $val })) }
            }
        }

        
        $wwK = Get-RegKeySafe ("$root\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery")
        if ($wwK) {
            $wwLwt = Get-RegKeyLastWriteUtc $wwK
            $wwOrder = Get-MruListExOrder $wwK
            $wwMostRecent = $(if ($wwOrder.Count -gt 0) { [string]$wwOrder[0] } else { $null })
            foreach ($vn in $wwK.GetValueNames()) {
                if ($vn -notmatch '^\d+$') { continue }
                $data = $null; try { $data = [byte[]]$wwK.GetValue($vn) } catch { }
                if (-not $data) { continue }
                $term = Get-Utf16FromBytes -Bytes $data -Start 0
                if ($term) {
                    $tsUtc = $null; $tsConf = 'Ninguna'
                    if ($wwMostRecent -and $vn -eq $wwMostRecent -and $wwLwt) { $tsUtc = $wwLwt.ToString($script:TsFmt); $tsConf = 'Aproximada' }
                    [void]$wwRecs.Add((New-Object PSObject -Property @{ User = $acct; SID = $sid; SearchTerm = $term; TimestampUTC = $tsUtc; TimestampConfidence = $tsConf }))
                }
            }
        }

        
        $urlK = Get-RegKeySafe ("$root\Software\Microsoft\Internet Explorer\TypedURLs")
        if ($urlK) {
            foreach ($vn in $urlK.GetValueNames()) {
                $val = $null; try { $val = [string]$urlK.GetValue($vn) } catch { }
                if ($val) { [void]$urlRecs.Add((New-Object PSObject -Property @{ User = $acct; SID = $sid; Slot = $vn; Url = $val })) }
            }
        }

        
        $bagRoots = @(
            "$root\Software\Microsoft\Windows\Shell\BagMRU",
            "Registry::HKEY_USERS\${sid}_Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU"
        )
        foreach ($br in $bagRoots) {
            $start = Get-RegKeySafe $br
            if ($null -eq $start) { continue }
            $stack = New-Object System.Collections.Stack
            $stack.Push($br)
            $nodes = 0
            while ($stack.Count -gt 0 -and $nodes -lt 4000) {
                $curPath = $stack.Pop(); $nodes++
                $ck = Get-RegKeySafe $curPath
                if ($null -eq $ck) { continue }
                foreach ($vn in $ck.GetValueNames()) {
                    if ($vn -notmatch '^\d+$') { continue }
                    $data = $null; try { $data = [byte[]]$ck.GetValue($vn) } catch { }
                    if (-not $data) { continue }
                    foreach ($run in (Get-Utf16Runs -Bytes $data -Min 3)) {
                        
                        if ($run -match '^[A-Za-z0-9 _\.\-\(\)\[\]&]+$' -and $run.Length -ge 3 -and $run -notmatch '^\d+$') {
                            [void]$sbRecs.Add((New-Object PSObject -Property @{ User = $acct; SID = $sid; FolderOrItem = $run; Hive = $(if ($br -match '_Classes') { 'UsrClass' } else { 'NTUSER' }) }))
                        }
                    }
                }
                try { foreach ($skn in $ck.GetSubKeyNames()) { if ($skn -match '^\d+$') { $stack.Push(($curPath + '\' + $skn)) } } } catch { }
            }
        }
    }

    
    if ($sbRecs.Count -gt 0) {
        $seen = @{}; $sbClean = New-Object System.Collections.ArrayList
        foreach ($r in $sbRecs) {
            $key = ($r.SID + '|' + $r.FolderOrItem)
            if (-not $seen.ContainsKey($key)) { $seen[$key] = $true; [void]$sbClean.Add($r) }
        }
        $sbRecs = $sbClean
    }

    
    if ($uaRecs.Count -gt 0)  { Export-ObjectData -Data @($uaRecs | Sort-Object LastRunUTC -Descending) -BaseName '30_userassist' -Category 'UserActivity' }
    else { Register-MissingEvidence -Evidence 'UserAssist' -Reason 'Sin entradas UserAssist accesibles en las hives cargadas' }
    if ($rdRecs.Count -gt 0)  { Export-ObjectData -Data $rdRecs -BaseName '31_recent_docs' -Category 'UserActivity' }
    if ($runRecs.Count -gt 0) { Export-ObjectData -Data $runRecs -BaseName '32_run_mru' -Category 'UserActivity' }
    if ($tpRecs.Count -gt 0)  { Export-ObjectData -Data $tpRecs -BaseName '33_typed_paths' -Category 'UserActivity' }
    if ($wwRecs.Count -gt 0)  { Export-ObjectData -Data $wwRecs -BaseName '34_explorer_searches' -Category 'UserActivity' }
    if ($urlRecs.Count -gt 0) { Export-ObjectData -Data $urlRecs -BaseName '35_typed_urls' -Category 'UserActivity' }
    if ($sbRecs.Count -gt 0)  { Export-ObjectData -Data $sbRecs -BaseName '36_shellbags' -Category 'UserActivity' }

    if ($timeline.Count -gt 0) {
        $tl = @($timeline | Sort-Object -Property TimestampUTC)
        $tlCsv = Join-Path $script:Paths.ParsedCSV '38_user_activity_timeline.csv'
        try {
            $tl | Export-Csv -LiteralPath $tlCsv -NoTypeInformation -Encoding UTF8
            Register-Evidence -Path $tlCsv -Category 'UserActivity' -SourceDescription 'Cronologia de actividad de usuario (UserAssist con fecha)'
        } catch { Write-ForensicLog -Level ERROR -Message ('Error exportando timeline de UserActivity: {0}' -f $_.Exception.Message) }
    }

    
    Register-MissingEvidence -Evidence 'ShellBags/RecentDocs (analisis exhaustivo y perfiles no cargados)' -Reason 'La extraccion en vivo de ShellBags es best-effort (nombres); el parseo estructurado completo (con marcas de tiempo por carpeta) y los perfiles de usuarios sin sesion se realizan offline sobre NTUSER.DAT/UsrClass.dat (ShellBags Explorer, RegRipper).'
    Write-ForensicLog -Message ('UserActivity: UserAssist={0}, RecentDocs={1}, RunMRU={2}, TypedPaths={3}, Busquedas={4}, TypedURLs={5}, ShellBags={6}.' -f $uaRecs.Count, $rdRecs.Count, $runRecs.Count, $tpRecs.Count, $wwRecs.Count, $urlRecs.Count, $sbRecs.Count)
    Write-ForensicLog -Message 'Modulo UserActivity completado.'
}

function Invoke-ModulePasswordActivity {
    Write-ForensicLog -Message '--- MODULO PasswordActivity ---'
    Register-Source 'Actividad de contrasenas/cuentas/grupos (eventos 4723/4724/4738/47xx, comandos y estado local)'

    $actionMap = @{
        '4723' = 'Cambio de contrasena (por el propio usuario)'
        '4724' = 'Restablecimiento de contrasena (por admin/otra cuenta)'
        '4794' = 'Intento de set de contrasena del modo DSRM'
        '4738' = 'Cuenta modificada (puede incluir cambio de contrasena)'
        '4720' = 'Cuenta creada'
        '4722' = 'Cuenta habilitada'
        '4725' = 'Cuenta deshabilitada'
        '4726' = 'Cuenta eliminada'
        '4740' = 'Cuenta bloqueada'
        '4767' = 'Cuenta desbloqueada'
        '4781' = 'Cuenta renombrada'
        '5376' = 'Credenciales de Credential Manager respaldadas'
        '5377' = 'Credenciales de Credential Manager restauradas'
        '4727' = 'Grupo global de seguridad creado'
        '4728' = 'Miembro anadido a grupo global de seguridad'
        '4729' = 'Miembro eliminado de grupo global de seguridad'
        '4730' = 'Grupo global de seguridad eliminado'
        '4731' = 'Grupo local de seguridad creado'
        '4732' = 'Miembro anadido a grupo local de seguridad'
        '4733' = 'Miembro eliminado de grupo local de seguridad'
        '4734' = 'Grupo local de seguridad eliminado'
        '4735' = 'Grupo local de seguridad modificado'
        '4737' = 'Grupo global de seguridad modificado'
        '4754' = 'Grupo universal de seguridad creado'
        '4755' = 'Grupo universal de seguridad modificado'
        '4756' = 'Miembro anadido a grupo universal de seguridad'
        '4757' = 'Miembro eliminado de grupo universal de seguridad'
        '4758' = 'Grupo universal de seguridad eliminado'
        '4764' = 'Tipo de grupo cambiado'
    }
    $pwIds  = @(4723,4724,4794,4738,4720,4722,4725,4726,4740,4767,4781,5376,5377)
    $grpIds = @(4727,4728,4729,4730,4731,4732,4733,4734,4735,4737,4754,4755,4756,4757,4758,4764)
    $allIds = $pwIds + $grpIds

    $timeline = New-Object System.Collections.ArrayList
    $pwRecs   = New-Object System.Collections.ArrayList
    $grpRecs  = New-Object System.Collections.ArrayList

    
    
    
    
    
    
    
    $ipByUser = @{}
    $secCsvPath = Join-Path $script:Paths.ParsedCSV '20_security_events.csv'
    $secCsvExists = Test-Path -LiteralPath $secCsvPath
    if ($secCsvExists) {
        try {
            foreach ($row in @(Import-Csv -LiteralPath $secCsvPath | Where-Object { $_.EventId -eq '4624' })) {
                $tu = [string]$row.User; $ip = [string]$row.SourceIP
                if ($tu -and $ip -and $ip -ne '-' -and $ip -ne '::1' -and $ip -ne '127.0.0.1') {
                    $t = $null; try { $t = [datetime]$row.TimestampUTC } catch { }
                    if (-not $ipByUser.ContainsKey($tu)) { $ipByUser[$tu] = New-Object System.Collections.ArrayList }
                    [void]$ipByUser[$tu].Add((New-Object PSObject -Property @{ T = $(if ($t) { $t } else { (Get-Date '1970-01-01') }); IP = $ip }))
                }
            }
            Write-ForensicLog -Message 'PasswordActivity: correlacion de IP desde 20_security_events.csv (evidencia del propio caso; sin segunda consulta a Security).'
        } catch { Write-ForensicLog -Level WARN -Message ('PasswordActivity: no se pudo leer 20_security_events.csv para IP: {0}' -f $_.Exception.Message) }
    }
    
    $rsCsvPath = Join-Path $script:Paths.ParsedCSV '26_remote_sessions.csv'
    if (Test-Path -LiteralPath $rsCsvPath) {
        try {
            foreach ($row in @(Import-Csv -LiteralPath $rsCsvPath)) {
                $ip = [string]$row.SourceIP
                if (-not $ip -or $ip -eq '-' -or $ip -eq '::1' -or $ip -eq '127.0.0.1') { continue }
                $t = $null; try { $t = [datetime]$row.TimestampUTC } catch { }
                foreach ($uu in @([string]$row.User, ([string]$row.User -replace '^.*\\', ''))) {
                    if (-not $uu) { continue }
                    if (-not $ipByUser.ContainsKey($uu)) { $ipByUser[$uu] = New-Object System.Collections.ArrayList }
                    [void]$ipByUser[$uu].Add((New-Object PSObject -Property @{ T = $(if ($t) { $t } else { (Get-Date '1970-01-01') }); IP = $ip }))
                }
            }
            Write-ForensicLog -Message 'PasswordActivity: IPs de sesiones RDP incorporadas a la correlacion (acceso externo por RDP).'
        } catch { }
    } else {
        
        try {
            $logons = @(Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4624; StartTime=$StartDate; EndTime=$EndDate } -ErrorAction Stop)
            foreach ($l in $logons) {
                $d = Get-EventDataHash $l
                $ip = $d['IpAddress']; $tu = $d['TargetUserName']
                if ($tu -and $ip -and $ip -ne '-' -and $ip -ne '::1' -and $ip -ne '127.0.0.1') {
                    if (-not $ipByUser.ContainsKey($tu)) { $ipByUser[$tu] = New-Object System.Collections.ArrayList }
                    [void]$ipByUser[$tu].Add((New-Object PSObject -Property @{ T = $l.TimeCreated.ToUniversalTime(); IP = $ip }))
                }
            }
            Write-ForensicLog -Message ('PasswordActivity: {0} inicios 4624 cargados (consulta directa; EventLogs no se ejecuto antes).' -f $logons.Count)
        } catch { Write-ForensicLog -Level WARN -Message 'PasswordActivity: no se pudieron leer eventos 4624 para correlacion de IP.' }
    }

    
    
    
    
    
    $events = @()
    $directOk = $true
    if ($secCsvExists) {
        $directOk = $false
    } else {
        try {
            $events = @(Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=$allIds; StartTime=$StartDate; EndTime=$EndDate } -ErrorAction Stop)
        } catch {
            if ($_.Exception.Message -match 'No events|No se encontr|no se encontraron') { $events = @() }
            else { $directOk = $false; Write-ForensicLog -Level WARN -Message ('PasswordActivity: consulta directa a Security fallo ({0}); se probara 20_security_events.csv.' -f $_.Exception.Message) }
        }
    }

    $buildRecord = {
        param($ids, $tsL, $tsU, $subjUser, $subjSid, $target, $targetSid, $group, $member, $ip, $ipSrc, $computer, $notes)
        $action = $(if ($actionMap.ContainsKey([string]$ids)) { $actionMap[[string]$ids] } else { ('EventID ' + $ids) })
        $rec = New-Object PSObject -Property @{
            TimestampLocal = $tsL; TimestampUTC = $tsU; EventId = $ids; Action = $action
            ActorUser = $subjUser; ActorSID = $subjSid
            TargetUser = $target; TargetSID = $targetSid
            Group = $group; Member = $member
            SourceIP = $ip; IPSource = $ipSrc
            Computer = $computer; Notes = $notes
        }
        return $rec
    }

    if ($directOk -and $events.Count -gt 0) {
        foreach ($e in $events) {
            $d = Get-EventDataHash $e
            $ids = [int]$e.Id
            $tsUtcDt = $e.TimeCreated.ToUniversalTime()
            $tsU = $tsUtcDt.ToString($script:TsFmt)
            $tsL = $e.TimeCreated.ToString($script:TsFmt)
            $subjUser = $d['SubjectUserName']; $subjDom = $d['SubjectDomainName']; $subjSid = $d['SubjectUserSid']
            if ($subjDom -and $subjUser) { $actor = ('{0}\{1}' -f $subjDom, $subjUser) } else { $actor = $subjUser }
            $tgtUser = $d['TargetUserName']; $tgtDom = $d['TargetDomainName']; $tgtSid = $d['TargetSid']; if (-not $tgtSid) { $tgtSid = $d['TargetUserSid'] }
            $member = $d['MemberName']; if (-not $member) { $member = $d['MemberSid'] }
            $group = $null; $target = $null; $targetSid = $tgtSid
            if ($grpIds -contains $ids) {
                $group = $(if ($tgtDom -and $tgtUser) { ('{0}\{1}' -f $tgtDom, $tgtUser) } else { $tgtUser })
                $target = $member
                if ($d['MemberSid']) { $targetSid = $d['MemberSid'] }
            } else {
                $target = $(if ($tgtDom -and $tgtUser) { ('{0}\{1}' -f $tgtDom, $tgtUser) } else { $tgtUser })
            }
            
            $ip = $d['IpAddress']; $ipSrc = $null
            if ($ip -and $ip -ne '-') { $ipSrc = 'Directa (evento)' }
            else {
                $inf = Resolve-SessionIp -Map $ipByUser -User $subjUser -WhenUtc $tsUtcDt
                if ($inf) { $ip = $inf; $ipSrc = 'Correlacionada (sesion 4624 del actor)' } else { $ip = $null; $ipSrc = 'No registrada por este evento' }
            }
            $notes = $null
            $extra = New-Object System.Collections.ArrayList
            foreach ($k in @('PrivilegeList','OldTargetUserName','NewTargetUserName','SamAccountName','DisplayName')) { if ($d[$k]) { [void]$extra.Add(('{0}={1}' -f $k, $d[$k])) } }
            if ($extra.Count -gt 0) { $notes = ($extra -join '; ') }

            $rec = & $buildRecord $ids $tsL $tsU $actor $subjSid $target $targetSid $group $member $ip $ipSrc $e.MachineName $notes
            if ($grpIds -contains $ids) { [void]$grpRecs.Add($rec) } else { [void]$pwRecs.Add($rec) }

            $tlFile = $(if ($group) { ('{0} (miembro: {1})' -f $group, $target) } else { $target })
            [void]$timeline.Add((New-Object PSObject -Property @{
                TimestampUTC = $tsU; TimestampLocal = $tsL; Event = $rec.Action; EventId = $ids
                Actor = $actor; Target = $tlFile; SourceIP = $ip; Source = ('Security ' + $ids); Confidence = 'Alta'
            }))
        }
        Write-ForensicLog -Message ('PasswordActivity: {0} eventos de contrasena/cuenta, {1} de grupos (consulta directa).' -f $pwRecs.Count, $grpRecs.Count)
    } else {
        
        $secCsv = Join-Path $script:Paths.ParsedCSV '20_security_events.csv'
        if (Test-Path -LiteralPath $secCsv) {
            try {
                foreach ($row in @(Import-Csv -LiteralPath $secCsv)) {
                    $ids = 0; [void][int]::TryParse([string]$row.EventId, [ref]$ids)
                    if (-not ($allIds -contains $ids)) { continue }
                    $notes = [string]$row.Notes
                    $actor = $null; $m = [regex]::Match($notes, '(?i)SubjectUserName=([^;]+)'); if ($m.Success) { $actor = $m.Groups[1].Value.Trim() }
                    $asid = $null;  $m = [regex]::Match($notes, '(?i)SubjectUserSid=([^;]+)'); if ($m.Success) { $asid = $m.Groups[1].Value.Trim() }
                    $tgt = [string]$row.User; $tsid = [string]$row.UserSID
                    $mem = $null; $m = [regex]::Match($notes, '(?i)MemberName=([^;]+)'); if ($m.Success) { $mem = $m.Groups[1].Value.Trim() }
                    $group = $null; $target = $tgt
                    if ($grpIds -contains $ids) { $group = $tgt; $target = $mem }
                    $ip = [string]$row.SourceIP; $ipSrc = $(if ($ip -and $ip -ne '-') { 'Directa (evento)' } else { $ip = $null; 'No registrada por este evento' })
                    $rec = & $buildRecord $ids $row.TimestampLocal $row.TimestampUTC $actor $asid $target $tsid $group $mem $ip $ipSrc $row.Computer $notes
                    if ($grpIds -contains $ids) { [void]$grpRecs.Add($rec) } else { [void]$pwRecs.Add($rec) }
                    [void]$timeline.Add((New-Object PSObject -Property @{
                        TimestampUTC = $row.TimestampUTC; TimestampLocal = $row.TimestampLocal; Event = $rec.Action; EventId = $ids
                        Actor = $actor; Target = $(if ($group) { $group + ' (miembro: ' + $target + ')' } else { $target }); SourceIP = $ip; Source = ('Security ' + $ids + ' [CSV]'); Confidence = 'Alta'
                    }))
                }
                Write-ForensicLog -Message ('PasswordActivity: {0} eventos de contrasena/cuenta, {1} de grupos (via 20_security_events.csv).' -f $pwRecs.Count, $grpRecs.Count)
            } catch { Write-ForensicLog -Level WARN -Message ('PasswordActivity: error leyendo 20_security_events.csv: {0}' -f $_.Exception.Message) }
        } else {
            Register-MissingEvidence -Evidence 'Eventos de contrasena/cuenta/grupo (Security)' -Reason 'Security.evtx no accesible (sin admin o auditoria de gestion de cuentas desactivada). Habilitar auditoria de "Administracion de cuentas".'
        }
    }
    if ($pwRecs.Count -gt 0)  { Export-ObjectData -Data $pwRecs  -BaseName '82_password_account_events' -Category 'PasswordActivity' }
    if ($grpRecs.Count -gt 0) { Export-ObjectData -Data $grpRecs -BaseName '84_group_membership_events' -Category 'PasswordActivity' }

    
    
    
    $cmdRecs = New-Object System.Collections.ArrayList
    $cmdRegex = '(?i)(net1?\s+user|Set-LocalUser|New-LocalUser|Rename-LocalUser|Set-ADAccountPassword|Set-ADUser|New-ADUser|\.SetPassword\(|\.ChangePassword\(|Add-LocalGroupMember|Remove-LocalGroupMember|net1?\s+localgroup|net1?\s+group|dsmod\s+user|dsadd\s+user|wmic\s+useraccount|chpasswd|Set-LocalGroup|ntdsutil)'
    $userExtract = '(?i)net1?\s+user\s+([^\s/]+)'

    $addCmd = {
        param($tsU, $src, $artifact, $rawCmd)
        $safe = Protect-CredentialInCommand $rawCmd
        $flagSecret = $(if ($rawCmd -ne $safe) { $true } else { $false })
        $tu = $null; $m = [regex]::Match($rawCmd, $userExtract); if ($m.Success) { $tu = $m.Groups[1].Value }
        $rec = New-Object PSObject -Property @{
            TimestampUTC = $tsU; Source = $src; Artifact = $artifact
            TargetUser = $tu; ContienePosibleContrasena = $flagSecret; Command = $safe
        }
        [void]$cmdRecs.Add($rec)
        [void]$timeline.Add((New-Object PSObject -Property @{
            TimestampUTC = $tsU; TimestampLocal = $null; Event = 'Comando de contrasena/grupo'; EventId = ''
            Actor = $null; Target = $tu; SourceIP = $null; Source = $src; Confidence = 'Probable'
        }))
    }

    
    $profiles = @(Get-CimOrWmi -ClassName 'Win32_UserProfile' | Where-Object { $_ -and -not $_.Special -and $_.LocalPath })
    foreach ($p in $profiles) {
        $hist = Join-Path $p.LocalPath 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
        if (-not (Test-Path -LiteralPath $hist)) { continue }
        $mt = $null; try { $mt = (Get-Item -LiteralPath $hist -Force).LastWriteTimeUtc.ToString($script:TsFmt) } catch { }
        try {
            foreach ($ln in (Get-Content -LiteralPath $hist -ErrorAction SilentlyContinue)) {
                if ($ln -match $cmdRegex) { & $addCmd $mt 'Historial PowerShell (sin marca por linea)' $hist $ln.Trim() }
            }
        } catch { }
    }
    
    $psCsv = Join-Path $script:Paths.ParsedCSV '22_powershell_events.csv'
    if (Test-Path -LiteralPath $psCsv) {
        try {
            foreach ($row in @(Import-Csv -LiteralPath $psCsv)) {
                $t = [string]$row.Notes
                if ($t -match $cmdRegex) { & $addCmd $row.TimestampUTC 'PowerShell 4104' 'Microsoft-Windows-PowerShell/Operational' $t }
            }
        } catch { }
    }
    
    $secCsv2 = Join-Path $script:Paths.ParsedCSV '20_security_events.csv'
    if (Test-Path -LiteralPath $secCsv2) {
        try {
            foreach ($row in @(Import-Csv -LiteralPath $secCsv2 | Where-Object { $_.EventId -eq '4688' })) {
                $cl = [string]$row.CommandLine
                if ($cl -and ($cl -match $cmdRegex)) { & $addCmd $row.TimestampUTC 'Proceso 4688 (linea de comandos)' 'Security.evtx' $cl }
            }
        } catch { }
    }
    if ($cmdRecs.Count -gt 0) { Export-ObjectData -Data $cmdRecs -BaseName '85_password_group_commands' -Category 'PasswordActivity' }
    else { Register-MissingEvidence -Evidence 'Comandos de contrasena/grupo' -Reason 'No se hallaron comandos de gestion de contrasenas/grupos en historial, 4104 ni 4688 disponibles' -Status 'EMPTY' }
    Write-ForensicLog -Message ('PasswordActivity: {0} comando(s) relacionados con contrasenas/grupos.' -f $cmdRecs.Count)

    
    
    
    $stateRecs = New-Object System.Collections.ArrayList
    if (Test-CommandAvailable 'Get-LocalUser') {
        try {
            
            $netUserCache = @{}
            foreach ($u in (Get-LocalUser -ErrorAction Stop)) {
                $lastLogon = $(if ($u.LastLogon) { $u.LastLogon.ToUniversalTime().ToString($script:TsFmt) } else { $null })
                $pwExpires = $(if ($u.PasswordExpires) { $u.PasswordExpires.ToUniversalTime().ToString($script:TsFmt) } elseif ($u.PasswordExpires -eq $null -and $u.Enabled) { 'No expira (por configuracion)' } else { $null })
                
                if (-not $lastLogon) {
                    try {
                        $nu = (& $env:ComSpec /c ('net user "{0}"' -f $u.Name) 2>$null)
                        if ($nu) {
                            $line = ($nu | Where-Object { $_ -match '(?i)ultimo inicio|last logon' } | Select-Object -First 1)
                            if ($line) {
                                $val = ($line -replace '(?i).*(ultimo inicio de sesi.n|last logon)\s*', '').Trim()
                                if ($val -and $val -notmatch '(?i)nunca|never') { $lastLogon = ('Segun net user: {0}' -f $val) }
                                elseif ($val -match '(?i)nunca|never') { $lastLogon = 'Nunca ha iniciado sesion' }
                            }
                        }
                    } catch { }
                }
                [void]$stateRecs.Add((New-Object PSObject -Property @{
                    Name = $u.Name; Enabled = $u.Enabled; SID = $u.SID.Value
                    PasswordLastSetUTC = $(if ($u.PasswordLastSet) { $u.PasswordLastSet.ToUniversalTime().ToString($script:TsFmt) } else { $null })
                    PasswordExpiresUTC = $pwExpires
                    PasswordChangeableUTC = $(if ($u.PasswordChangeableDate) { $u.PasswordChangeableDate.ToUniversalTime().ToString($script:TsFmt) } else { $null })
                    PasswordRequired = $u.PasswordRequired; UserMayChangePassword = $u.UserMayChangePassword
                    LastLogonUTC = $lastLogon
                    Source = 'Get-LocalUser + net user'
                }))
            }
        } catch { Write-ForensicLog -Level WARN -Message ('PasswordActivity: Get-LocalUser fallo: {0}' -f $_.Exception.Message) }
    } else {
        foreach ($u in @(Get-CimOrWmi -ClassName 'Win32_UserAccount' -Filter 'LocalAccount=True')) {
            if ($null -eq $u) { continue }
            [void]$stateRecs.Add((New-Object PSObject -Property @{
                Name = $u.Name; Enabled = (-not $u.Disabled); SID = $u.SID
                PasswordLastSetUTC = $null; PasswordExpiresUTC = $u.PasswordExpires
                PasswordChangeableUTC = $u.PasswordChangeable; PasswordRequired = $u.PasswordRequired
                UserMayChangePassword = $null; LastLogonUTC = $null; Lockout = $u.Lockout
                Source = 'Win32_UserAccount (PasswordLastSet no disponible via WMI; usar Get-LocalUser o net user)'
            }))
        }
    }
    if ($stateRecs.Count -gt 0) { Export-ObjectData -Data $stateRecs -BaseName '86_local_account_password_state' -Category 'PasswordActivity' }
    
    Register-MissingEvidence -Evidence 'Historial de contrasenas de cuentas de dominio' -Reason 'No obtenible desde el endpoint: consultar el controlador de dominio (eventos 4723/4724 del DC, atributos pwdLastSet en AD).'

    
    
    
    if ($timeline.Count -gt 0) {
        $tl = @($timeline | Sort-Object -Property TimestampUTC)
        $tlCsv = Join-Path $script:Paths.ParsedCSV '87_password_activity_timeline.csv'
        try {
            $tl | Export-Csv -LiteralPath $tlCsv -NoTypeInformation -Encoding UTF8
            Register-Evidence -Path $tlCsv -Category 'PasswordActivity' -SourceDescription 'Cronologia de actividad de contrasenas/cuentas/grupos'
        } catch { Write-ForensicLog -Level ERROR -Message ('Error exportando timeline de PasswordActivity: {0}' -f $_.Exception.Message) }
    }

    Write-ForensicLog -Message 'Modulo PasswordActivity completado.'
}








function Invoke-ModuleProgramExecution {
    Write-ForensicLog -Message '--- MODULO ProgramExecution ---'
    Register-Source 'BAM/DAM (ultima ejecucion por usuario con fecha) - HKLM\SYSTEM'
    if (-not $script:IsAdmin) {
        Register-MissingEvidence -Evidence 'BAM/DAM (ejecucion por usuario)' -Reason 'Requiere administrador para leer HKLM\SYSTEM\...\bam. Sin ello no se obtiene la ultima ejecucion fechada por SID.'
        return
    }
    $bamRecs = New-Object System.Collections.ArrayList
    $timeline = New-Object System.Collections.ArrayList
    $bamRoots = @(
        @{ Root='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings'; Src='BAM' },
        @{ Root='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\UserSettings';       Src='BAM' },
        @{ Root='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dam\State\UserSettings'; Src='DAM' }
    )
    foreach ($br in $bamRoots) {
        $rk = Get-RegKeySafe $br.Root
        if ($null -eq $rk) { continue }
        $sidNames = @(); try { $sidNames = $rk.GetSubKeyNames() } catch { }
        foreach ($sidName in $sidNames) {
            if ($sidName -notmatch '^S-1-5-21-') { continue }
            $acct = $sidName
            try { $acct = (New-Object System.Security.Principal.SecurityIdentifier($sidName)).Translate([System.Security.Principal.NTAccount]).Value } catch { }
            $sk = Get-RegKeySafe ($br.Root + '\' + $sidName)
            if ($null -eq $sk) { continue }
            foreach ($vn in $sk.GetValueNames()) {
                if (-not $vn -or $vn -eq 'Version' -or $vn -eq 'SequenceNumber') { continue }
                $data = $null; try { $data = [byte[]]$sk.GetValue($vn) } catch { }
                if (-not $data -or $data.Length -lt 8) { continue }
                $lastRun = $null
                try { $ft = [BitConverter]::ToInt64($data, 0); if ($ft -gt 0) { $lastRun = [DateTime]::FromFileTimeUtc($ft).ToString($script:TsFmt) } } catch { }
                
                $prog = $vn -replace '(?i)^\\Device\\HarddiskVolume\d+\\', 'C:\'
                [void]$bamRecs.Add((New-Object PSObject -Property @{
                    User = $acct; SID = $sidName; Program = $prog; LastRunUTC = $lastRun; Source = $br.Src
                }))
                if ($lastRun) {
                    [void]$timeline.Add((New-Object PSObject -Property @{
                        TimestampUTC = $lastRun; User = $acct; Event = 'Ultima ejecucion (BAM/DAM)'; Item = $prog; Source = $br.Src
                    }))
                }
            }
        }
    }
    if ($bamRecs.Count -gt 0) {
        Export-ObjectData -Data @($bamRecs | Sort-Object LastRunUTC -Descending) -BaseName '43_program_execution_bam' -Category 'ProgramExecution'
        Write-ForensicLog -Message ('ProgramExecution: {0} entradas BAM/DAM (ultima ejecucion por usuario).' -f $bamRecs.Count)
    } else {
        Register-MissingEvidence -Evidence 'BAM/DAM' -Reason 'Sin entradas BAM/DAM (version de Windows sin BAM o claves vacias)'
    }
    if ($timeline.Count -gt 0) {
        $tlCsv = Join-Path $script:Paths.ParsedCSV '43b_program_execution_timeline.csv'
        try { @($timeline | Sort-Object TimestampUTC) | Export-Csv -LiteralPath $tlCsv -NoTypeInformation -Encoding UTF8; Register-Evidence -Path $tlCsv -Category 'ProgramExecution' -SourceDescription 'Cronologia de ultima ejecucion (BAM/DAM)' } catch { }
    }
    Write-ForensicLog -Message 'Modulo ProgramExecution completado.'
}







function Read-UsbTimestamp {
    
    param([string]$DeviceBase, [string]$PropId)
    $guid = '{83da6326-97a6-4088-9453-a1923f573b29}'
    foreach ($cand in @(($DeviceBase + '\Properties\' + $guid + '\' + $PropId + '\00000000'), ($DeviceBase + '\Properties\' + $guid + '\' + $PropId))) {
        $k = Get-RegKeySafe $cand
        if ($null -eq $k) { continue }
        foreach ($vn in @('', '(default)')) {
            $data = $null; try { $data = [byte[]]$k.GetValue($vn) } catch { }
            if ($data -and $data.Length -ge 8) {
                try { $ft = [BitConverter]::ToInt64($data, 0); if ($ft -gt 0) { return [DateTime]::FromFileTimeUtc($ft).ToString($script:TsFmt) } } catch { }
            }
        }
    }
    return $null
}

function Invoke-ModuleUSBDevices {
    Write-ForensicLog -Message '--- MODULO USBDevices ---'
    Register-Source 'USBSTOR / USB / MountedDevices / Windows Portable Devices'
    $usbRecs = New-Object System.Collections.ArrayList
    $timeline = New-Object System.Collections.ArrayList

    $storRoot = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR'
    $stor = Get-RegKeySafe $storRoot
    if ($null -eq $stor) {
        Register-MissingEvidence -Evidence 'Dispositivos USB (USBSTOR)' -Reason 'Clave USBSTOR no accesible (requiere administrador) o sin dispositivos de almacenamiento USB registrados'
    } else {
        $devNames = @(); try { $devNames = $stor.GetSubKeyNames() } catch { }
        foreach ($devName in $devNames) {
            $devKey = $storRoot + '\' + $devName
            $dk = Get-RegKeySafe $devKey
            if ($null -eq $dk) { continue }
            $serials = @(); try { $serials = $dk.GetSubKeyNames() } catch { }
            foreach ($serial in $serials) {
                $instBase = $devKey + '\' + $serial
                $inst = Get-RegKeySafe $instBase
                if ($null -eq $inst) { continue }
                $friendly = $null; try { $friendly = [string]$inst.GetValue('FriendlyName') } catch { }
                $first = Read-UsbTimestamp -DeviceBase $instBase -PropId '0064'
                $lastConn = Read-UsbTimestamp -DeviceBase $instBase -PropId '0066'
                $lastRem = Read-UsbTimestamp -DeviceBase $instBase -PropId '0067'
                
                $serialClean = ($serial -split '&')[0]
                [void]$usbRecs.Add((New-Object PSObject -Property @{
                    FriendlyName = $friendly; DeviceModel = $devName; Serial = $serialClean; SerialRaw = $serial
                    FirstConnectUTC = $first; LastConnectUTC = $lastConn; LastRemovedUTC = $lastRem
                }))
                foreach ($ev in @(@{T=$first;E='Primera conexion USB'}, @{T=$lastConn;E='Ultima conexion USB'}, @{T=$lastRem;E='Ultima extraccion USB'})) {
                    if ($ev.T) { [void]$timeline.Add((New-Object PSObject -Property @{ TimestampUTC=$ev.T; Event=$ev.E; Device=$friendly; Serial=$serialClean; Source='USBSTOR' })) }
                }
            }
        }
    }
    
    $wpd = Get-RegKeySafe 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Portable Devices\Devices'
    $wpdList = New-Object System.Collections.ArrayList
    if ($wpd) {
        foreach ($dn in @($wpd.GetSubKeyNames())) {
            $k = Get-RegKeySafe ('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Portable Devices\Devices\' + $dn)
            if ($k) { $fn = $null; try { $fn = [string]$k.GetValue('FriendlyName') } catch { }; if ($fn) { [void]$wpdList.Add((New-Object PSObject -Property @{ DeviceId=$dn; FriendlyName=$fn })) } }
        }
    }

    if ($usbRecs.Count -gt 0) {
        Export-ObjectData -Data $usbRecs -BaseName '44_usb_devices' -Category 'USBDevices'
        Write-ForensicLog -Message ('USBDevices: {0} dispositivo(s) de almacenamiento USB catalogados.' -f $usbRecs.Count)
    }
    if ($wpdList.Count -gt 0) { Export-ObjectData -Data $wpdList -BaseName '44b_portable_devices' -Category 'USBDevices' }
    if ($timeline.Count -gt 0) {
        $tlCsv = Join-Path $script:Paths.ParsedCSV '44c_usb_timeline.csv'
        try { @($timeline | Sort-Object TimestampUTC) | Export-Csv -LiteralPath $tlCsv -NoTypeInformation -Encoding UTF8; Register-Evidence -Path $tlCsv -Category 'USBDevices' -SourceDescription 'Cronologia de conexiones USB' } catch { }
    }
    
    $setupapi = Join-Path (Get-WinEnvPath SystemRoot) 'inf\setupapi.dev.log'
    if (Test-Path -LiteralPath $setupapi) {
        Copy-EvidenceFile -SourcePath $setupapi -DestinationPath (Join-Path $script:Paths.RawFS 'setupapi.dev.log') -Category 'USBDevices' -Notes 'Log de instalacion de dispositivos (primera conexion fechada)' | Out-Null
    }
    Write-ForensicLog -Message 'Modulo USBDevices completado.'
}









$script:WinSqliteReady = $null
function Initialize-WinSqlite {
    




    if ($null -ne $script:WinSqliteReady) { return $script:WinSqliteReady }
    $script:WinSqliteReady = $false
    $sysRoot = $env:SystemRoot; if (-not $sysRoot) { $sysRoot = $env:windir }
    if (-not $sysRoot) { return $false }
    $dll = Join-Path $sysRoot 'System32\winsqlite3.dll'
    if (-not (Test-Path -LiteralPath $dll)) { return $false }
    try {
        if (-not ([System.Management.Automation.PSTypeName]'Forensic.WinSqlite').Type) {
            Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Text;
namespace Forensic {
  public static class WinSqlite {
    [DllImport("winsqlite3.dll", EntryPoint="sqlite3_open_v2", CallingConvention=CallingConvention.Cdecl)]
    static extern int sqlite3_open_v2(byte[] filename, out IntPtr db, int flags, IntPtr vfs);
    [DllImport("winsqlite3.dll", EntryPoint="sqlite3_close", CallingConvention=CallingConvention.Cdecl)]
    static extern int sqlite3_close(IntPtr db);
    [DllImport("winsqlite3.dll", EntryPoint="sqlite3_prepare_v2", CallingConvention=CallingConvention.Cdecl)]
    static extern int sqlite3_prepare_v2(IntPtr db, byte[] sql, int nByte, out IntPtr stmt, IntPtr tail);
    [DllImport("winsqlite3.dll", EntryPoint="sqlite3_step", CallingConvention=CallingConvention.Cdecl)]
    static extern int sqlite3_step(IntPtr stmt);
    [DllImport("winsqlite3.dll", EntryPoint="sqlite3_column_count", CallingConvention=CallingConvention.Cdecl)]
    static extern int sqlite3_column_count(IntPtr stmt);
    [DllImport("winsqlite3.dll", EntryPoint="sqlite3_column_text", CallingConvention=CallingConvention.Cdecl)]
    static extern IntPtr sqlite3_column_text(IntPtr stmt, int col);
    [DllImport("winsqlite3.dll", EntryPoint="sqlite3_finalize", CallingConvention=CallingConvention.Cdecl)]
    static extern int sqlite3_finalize(IntPtr stmt);
    const int SQLITE_OK=0, SQLITE_ROW=100, SQLITE_OPEN_READONLY=1;
    static byte[] Utf8(string s){ return Encoding.UTF8.GetBytes(s + "\0"); }
    // Abre en solo-lectura con URI para no bloquear (immutable=1 evita problemas de lock/WAL)
    public static List<string[]> Query(string path, string sql, int maxRows){
      var rows = new List<string[]>();
      IntPtr db;
      string uri = "file:" + path.Replace("\\","/") + "?immutable=1";
      if (sqlite3_open_v2(Utf8(uri), out db, SQLITE_OPEN_READONLY|0x00000040, IntPtr.Zero) != SQLITE_OK) { if(db!=IntPtr.Zero) sqlite3_close(db); return rows; }
      IntPtr stmt;
      if (sqlite3_prepare_v2(db, Utf8(sql), -1, out stmt, IntPtr.Zero) != SQLITE_OK) { sqlite3_close(db); return rows; }
      int cols = sqlite3_column_count(stmt);
      while (sqlite3_step(stmt) == SQLITE_ROW && rows.Count < maxRows) {
        var r = new string[cols];
        for (int i=0;i<cols;i++){ IntPtr p = sqlite3_column_text(stmt, i); r[i] = (p==IntPtr.Zero) ? null : PtrToStringUtf8(p); }
        rows.Add(r);
      }
      sqlite3_finalize(stmt); sqlite3_close(db);
      return rows;
    }
    static string PtrToStringUtf8(IntPtr p){
      int len=0; while(Marshal.ReadByte(p,len)!=0) len++;
      byte[] b=new byte[len]; Marshal.Copy(p,b,0,len); return Encoding.UTF8.GetString(b);
    }
  }
}
"@ -ErrorAction Stop
        }
        $script:WinSqliteReady = $true
    } catch {
        Write-ForensicLog -Level DEBUG -Message ('winsqlite3 no disponible: {0}' -f $_.Exception.Message)
        $script:WinSqliteReady = $false
    }
    return $script:WinSqliteReady
}

function ConvertFrom-WebKitTime {
    
    param($Value)
    if (-not $Value) { return $null }
    try {
        $n = [int64]$Value; if ($n -le 0) { return $null }
        $dt = [datetime]::FromFileTimeUtc($n * 10)  
        return $dt.ToString($script:TsFmt)
    } catch { return $null }
}

function ConvertFrom-PRTime {
    
    param($Value)
    if (-not $Value) { return $null }
    try {
        $n = [int64]$Value; if ($n -le 0) { return $null }
        $dt = [datetime]'1970-01-01T00:00:00Z'; $dt = $dt.AddMilliseconds($n / 1000.0)
        return $dt.ToUniversalTime().ToString($script:TsFmt)
    } catch { return $null }
}

function Invoke-ModuleBrowserActivity {
    Write-ForensicLog -Message '--- MODULO BrowserActivity ---'
    Register-Source 'Historial de navegadores (Chrome/Edge/Firefox/Brave): preservacion + extraccion de URLs'
    $bDir = Join-Path $script:Paths.RawFS 'Browsers'
    $urlRecs = New-Object System.Collections.ArrayList
    $aiRecs = New-Object System.Collections.ArrayList
    $histRecs = New-Object System.Collections.ArrayList   
    $dlRecs = New-Object System.Collections.ArrayList     
    $seen = @{}
    $sqliteOk = Initialize-WinSqlite
    if ($sqliteOk) { Write-ForensicLog -Message 'BrowserActivity: winsqlite3 disponible; historial con FECHAS por visita.' }
    else { Write-ForensicLog -Level WARN -Message 'BrowserActivity: winsqlite3 no disponible; se extraen URLs sin fecha (parseo con fecha se hara offline).' }
    $aiRe = '(?i)(chatgpt\.com|chat\.openai\.com|openai\.com|claude\.ai|anthropic\.com|gemini\.google\.com|bard\.google\.com|copilot\.microsoft\.com|copilot\.cloud\.microsoft|perplexity\.ai|poe\.com|character\.ai|huggingface\.co|deepseek\.com|mistral\.ai|you\.com)'
    $cloudRe = '(?i)(mega\.nz|drive\.google\.com|dropbox\.com|wetransfer\.com|mediafire\.com|onedrive\.live\.com|1drv\.ms|sendspace|gofile\.io|anonfiles|file\.io|pcloud\.com|icloud\.com)'
    $urlRe = [regex]'(?i)https?://[A-Za-z0-9\.\-]+(?:/[^\s"''<>\\\x00-\x1F]{0,180})?'

    $profiles = @(Get-CimOrWmi -ClassName 'Win32_UserProfile' | Where-Object { $_ -and -not $_.Special -and $_.LocalPath })
    foreach ($p in $profiles) {
        $lp = $p.LocalPath
        $pUser = $null; try { $pUser = (New-Object System.Security.Principal.SecurityIdentifier($p.SID)).Translate([System.Security.Principal.NTAccount]).Value } catch { }
        $sidSafe = ($p.SID -replace '[^A-Za-z0-9-]', '_')
        $dbs = New-Object System.Collections.ArrayList
        
        $chromiumBases = @(
            @{ B='Chrome'; D=(Join-Path $lp 'AppData\Local\Google\Chrome\User Data') },
            @{ B='Edge';   D=(Join-Path $lp 'AppData\Local\Microsoft\Edge\User Data') },
            @{ B='Brave';  D=(Join-Path $lp 'AppData\Local\BraveSoftware\Brave-Browser\User Data') }
        )
        foreach ($cb in $chromiumBases) {
            if (-not (Test-Path -LiteralPath $cb.D)) { continue }
            foreach ($prof in @('Default', 'Profile 1', 'Profile 2', 'Profile 3')) {
                foreach ($fn in @('History', 'Web Data', 'Shortcuts')) {
                    $f = Join-Path (Join-Path $cb.D $prof) $fn
                    if (Test-Path -LiteralPath $f) { [void]$dbs.Add((New-Object PSObject -Property @{ Browser=$cb.B; Profile=$prof; File=$f })) }
                }
            }
        }
        
        $ffProfiles = Join-Path $lp 'AppData\Roaming\Mozilla\Firefox\Profiles'
        if (Test-Path -LiteralPath $ffProfiles) {
            foreach ($pf in @(Get-ChildItem -LiteralPath $ffProfiles -Directory -Force -ErrorAction SilentlyContinue)) {
                foreach ($fn in @('places.sqlite', 'formhistory.sqlite')) {
                    $f = Join-Path $pf.FullName $fn
                    if (Test-Path -LiteralPath $f) { [void]$dbs.Add((New-Object PSObject -Property @{ Browser='Firefox'; Profile=$pf.Name; File=$f })) }
                }
            }
        }
        foreach ($db in $dbs) {
            
            $dest = Join-Path (Join-Path $bDir ($db.Browser + '_' + $sidSafe + '_' + ($db.Profile -replace '\s','_'))) (Split-Path $db.File -Leaf)
            Copy-EvidenceFile -SourcePath $db.File -DestinationPath $dest -Category 'BrowserActivity' -Notes ('Historial/BBDD de ' + $db.Browser) | Out-Null
            
            $srcDb = $(if (Test-Path -LiteralPath $dest) { $dest } else { $db.File })
            $leaf = (Split-Path $db.File -Leaf)
            if ($sqliteOk -and (Test-Path -LiteralPath $srcDb)) {
                try {
                    if ($leaf -eq 'History') {
                        
                        $q = 'SELECT u.url, u.title, v.visit_time, u.visit_count, u.typed_count FROM visits v JOIN urls u ON u.id = v.url ORDER BY v.visit_time DESC LIMIT 20000'
                        foreach ($r in [Forensic.WinSqlite]::Query($srcDb, $q, 20000)) {
                            $tsUtc = ConvertFrom-WebKitTime $r[2]
                            $u = [string]$r[0]; if (-not $u) { continue }
                            $cat = 'Otro'; if ($u -match $aiRe) { $cat = 'IA' } elseif ($u -match $cloudRe) { $cat = 'Nube/Transferencia' }
                            [void]$histRecs.Add((New-Object PSObject -Property @{
                                TimestampUTC=$tsUtc; TimestampLocal=$(if($tsUtc){ConvertTo-MadridTimeString ([datetime]::Parse($tsUtc).ToUniversalTime())}else{$null})
                                User=$pUser; Browser=$db.Browser; Profile=$db.Profile; Category=$cat
                                Url=$u; Title=[string]$r[1]; VisitCount=$r[3]; TypedCount=$r[4]
                                EvidenceSource=('SQLite ' + $leaf + ' (tabla visits)'); Confidence='Alta'
                            }))
                            if ($cat -eq 'IA') { [void]$aiRecs.Add((New-Object PSObject -Property @{ TimestampUTC=$tsUtc; User=$pUser; Browser=$db.Browser; Servicio=($u -replace '(?i)^https?://([^/]+).*','$1'); Url=$u })) }
                        }
                        
                        $qd = 'SELECT target_path, tab_url, start_time, end_time, total_bytes FROM downloads ORDER BY start_time DESC LIMIT 5000'
                        foreach ($r in [Forensic.WinSqlite]::Query($srcDb, $qd, 5000)) {
                            [void]$dlRecs.Add((New-Object PSObject -Property @{
                                StartTimeUTC=(ConvertFrom-WebKitTime $r[2]); EndTimeUTC=(ConvertFrom-WebKitTime $r[3])
                                User=$pUser; Browser=$db.Browser; DownloadPath=[string]$r[0]; SourceUrl=[string]$r[1]; Bytes=$r[4]
                                EvidenceSource=('SQLite ' + $leaf + ' (tabla downloads)')
                            }))
                        }
                    } elseif ($leaf -eq 'places.sqlite') {
                        
                        $q = 'SELECT p.url, p.title, h.visit_date, p.visit_count, p.typed FROM moz_historyvisits h JOIN moz_places p ON p.id = h.place_id ORDER BY h.visit_date DESC LIMIT 20000'
                        foreach ($r in [Forensic.WinSqlite]::Query($srcDb, $q, 20000)) {
                            $tsUtc = ConvertFrom-PRTime $r[2]
                            $u = [string]$r[0]; if (-not $u) { continue }
                            $cat = 'Otro'; if ($u -match $aiRe) { $cat = 'IA' } elseif ($u -match $cloudRe) { $cat = 'Nube/Transferencia' }
                            [void]$histRecs.Add((New-Object PSObject -Property @{
                                TimestampUTC=$tsUtc; TimestampLocal=$(if($tsUtc){ConvertTo-MadridTimeString ([datetime]::Parse($tsUtc).ToUniversalTime())}else{$null})
                                User=$pUser; Browser='Firefox'; Profile=$db.Profile; Category=$cat
                                Url=$u; Title=[string]$r[1]; VisitCount=$r[3]; TypedCount=$r[4]
                                EvidenceSource='SQLite places.sqlite (moz_historyvisits)'; Confidence='Alta'
                            }))
                            if ($cat -eq 'IA') { [void]$aiRecs.Add((New-Object PSObject -Property @{ TimestampUTC=$tsUtc; User=$pUser; Browser='Firefox'; Servicio=($u -replace '(?i)^https?://([^/]+).*','$1'); Url=$u })) }
                        }
                    }
                } catch { Write-ForensicLog -Level DEBUG -Message ('BrowserActivity: parsing SQLite fallo en {0}: {1}' -f $leaf, $_.Exception.Message) }
            }
            
            try {
                $fi = Get-Item -LiteralPath $db.File -Force -ErrorAction SilentlyContinue
                $srcForRead = $(if (Test-Path -LiteralPath $dest) { $dest } else { $db.File })
                if ($fi -and $fi.Length -le 150MB -and (Test-Path -LiteralPath $srcForRead)) {
                    $bytes = [System.IO.File]::ReadAllBytes($srcForRead)
                    $text = [System.Text.Encoding]::UTF8.GetString($bytes)
                    foreach ($mm in $urlRe.Matches($text)) {
                        $u = $mm.Value
                        if ($u.Length -lt 12 -or $u.Length -gt 200) { continue }
                        $key = $db.Browser + '|' + $u
                        if ($seen.ContainsKey($key)) { continue }
                        $seen[$key] = $true
                        $cat = 'Otro'
                        if ($u -match $aiRe) { $cat = 'IA' } elseif ($u -match $cloudRe) { $cat = 'Nube/Transferencia' }
                        if ($urlRecs.Count -lt 20000) {
                            [void]$urlRecs.Add((New-Object PSObject -Property @{ User=$pUser; Browser=$db.Browser; Profile=$db.Profile; Category=$cat; Url=$u }))
                        }
                        if ($cat -eq 'IA' -and $aiRecs.Count -lt 5000) {
                            [void]$aiRecs.Add((New-Object PSObject -Property @{ User=$pUser; Browser=$db.Browser; Servicio=($u -replace '(?i)^https?://([^/]+).*', '$1'); Url=$u }))
                        }
                    }
                }
            } catch { Write-ForensicLog -Level DEBUG -Message ('BrowserActivity: no se pudo extraer URLs de {0}: {1}' -f $db.File, $_.Exception.Message) }
        }
    }
    if ($urlRecs.Count -gt 0) { Export-ObjectData -Data $urlRecs -BaseName '45_browser_urls' -Category 'BrowserActivity' }
    else { Register-MissingEvidence -Evidence 'Historial de navegacion' -Reason 'Sin navegadores con historial accesible en los perfiles (o bases bloqueadas). Preservar y parsear offline.' }
    
    if ($histRecs.Count -gt 0) {
        Export-ObjectData -Data @($histRecs | Sort-Object TimestampUTC -Descending) -BaseName '47_browser_history_timeline' -Category 'BrowserActivity'
        Write-ForensicLog -Message ('BrowserActivity: {0} visitas con FECHA (historial cronologico).' -f $histRecs.Count)
    }
    if ($dlRecs.Count -gt 0) { Export-ObjectData -Data @($dlRecs | Sort-Object StartTimeUTC -Descending) -BaseName '48_browser_downloads' -Category 'BrowserActivity' }
    if ($aiRecs.Count -gt 0) {
        
        $dateByUrl = @{}; $dateByHost = @{}
        foreach ($h in $histRecs) { if ($h.TimestampUTC -and $h.Category -eq 'IA') {
            if (-not $dateByUrl.ContainsKey($h.Url)) { $dateByUrl[$h.Url] = $h.TimestampUTC }
            $hh = ($h.Url -replace '(?i)^https?://([^/]+).*','$1'); if (-not $dateByHost.ContainsKey($hh)) { $dateByHost[$hh] = $h.TimestampUTC } } }
        foreach ($d in $dlRecs) { if ($d.StartTimeUTC -and $d.SourceUrl -and -not $dateByUrl.ContainsKey($d.SourceUrl)) { $dateByUrl[$d.SourceUrl] = $d.StartTimeUTC } }
        foreach ($a in $aiRecs) {
            if (-not $a.TimestampUTC) {
                $ts = $null; $src = $null
                if ($dateByUrl.ContainsKey($a.Url)) { $ts = $dateByUrl[$a.Url]; $src = 'Visita/descarga datada de la misma URL' }
                elseif ($a.Servicio -and $dateByHost.ContainsKey($a.Servicio)) { $ts = $dateByHost[$a.Servicio]; $src = 'Visita datada del mismo servicio (misma sesion de navegacion)' }
                if ($ts) { $a.TimestampUTC = $ts; if ($a.PSObject.Properties['DateSource']) { $a.DateSource = $src } else { $a | Add-Member -NotePropertyName DateSource -NotePropertyValue $src -Force } }
            }
        }
        
        $aiRecs = @($aiRecs | Sort-Object @{E={[bool]$_.TimestampUTC};D=$true} | Group-Object Url | ForEach-Object { $_.Group | Select-Object -First 1 })
        Export-ObjectData -Data $aiRecs -BaseName '46_ai_web_usage' -Category 'BrowserActivity'
        Write-ForensicLog -Message ('BrowserActivity: detectado uso de servicios de IA por navegador ({0} URLs).' -f $aiRecs.Count)
    }
    if ($histRecs.Count -eq 0) {
        Register-MissingEvidence -Evidence 'Timeline exacto de navegacion (fecha por visita/descarga)' -Reason 'No se pudo parsear el SQLite en vivo (winsqlite3 no disponible o bases bloqueadas): la fecha por visita/descarga se obtiene offline sobre las BBDD preservadas (tablas urls/visits/downloads o moz_places/moz_historyvisits).' -Status 'REQUIRES_OFFLINE_ACQUISITION'
    }
    Write-ForensicLog -Message ('BrowserActivity: {0} URLs extraidas (best-effort). Modulo completado.' -f $urlRecs.Count)
}










function Get-LogonTypeName {
    param([string]$T)
    switch ([string]$T) {
        '2'  { '2 - Interactivo (teclado local)' }
        '3'  { '3 - Red (autenticacion remota: SMB, IIS, WinRM u otro; el protocolo no lo indica el tipo)' }
        '4'  { '4 - Proceso por lotes (tarea programada)' }
        '5'  { '5 - Servicio' }
        '7'  { '7 - Desbloqueo de pantalla' }
        '8'  { '8 - Red con credenciales en claro' }
        '9'  { '9 - Credenciales nuevas (RunAs /netonly)' }
        '10' { '10 - Escritorio remoto (RDP/Terminal Services)' }
        '11' { '11 - Interactivo con credenciales en cache' }
        '12' { '12 - Remoto interactivo en cache' }
        '13' { '13 - Desbloqueo con credenciales en cache' }
        default { $(if ($T) { 'Tipo ' + $T } else { '' }) }
    }
}

function Get-LogonClass {
    
    param([string]$User, [string]$LogonType)
    $u = ([string]$User).Trim()
    $ul = $u.ToLowerInvariant()
    if ($ul -in @('system','local service','network service','anonymous logon','local system')) { return 'Sistema' }
    if ($ul -like 'dwm-*' -or $ul -like 'umfd-*' -or $ul -like 'font driver host*') { return 'Sistema' }
    if ($u.EndsWith('$')) { return 'Maquina' }
    if (-not $u) { return 'Sistema' }
    if ($LogonType -eq '5') { return 'Servicio' }
    if ($LogonType -eq '4') { return 'Tarea' }
    if ($LogonType -eq '0') { return 'Indefinido' }
    return 'Humano'
}

function Invoke-ModuleLogonCorrelation {
    Write-ForensicLog -Message '--- MODULO LogonCorrelation ---'
    Register-Source 'Correlacion de inicios de sesion e IP (ventana del ataque vs. historico) - reutiliza 20_security_events.csv y 26_remote_sessions.csv'

    $secCsv = Join-Path $script:Paths.ParsedCSV '20_security_events.csv'
    $rsCsv  = Join-Path $script:Paths.ParsedCSV '26_remote_sessions.csv'
    if (-not (Test-Path -LiteralPath $secCsv)) {
        Register-MissingEvidence -Evidence 'Correlacion de inicios de sesion' -Reason 'Falta 20_security_events.csv (ejecutar con EventLogs). Sin los inicios de sesion no hay correlacion de IP.'
        return
    }

    
    $incS = $IncidentStart; $incE = $IncidentEnd
    if ($incS -eq [datetime]::MinValue) { $incS = $EndDate.AddDays(-7) }
    if ($incE -eq [datetime]::MinValue) { $incE = $EndDate }
    $incSUtc = $incS.ToUniversalTime(); $incEUtc = $incE.ToUniversalTime()
    $script:IncidentStartUtc = $incSUtc; $script:IncidentEndUtc = $incEUtc   
    Write-ForensicLog -Message ('LogonCorrelation: ventana del incidente {0} a {1} (UTC). Historico = anterior a {0} dentro del rango recogido.' -f $incSUtc.ToString($script:TsFmt), $incEUtc.ToString($script:TsFmt))

    
    $logons = New-Object System.Collections.ArrayList
    try {
        foreach ($r in @(Import-Csv -LiteralPath $secCsv | Where-Object { $_.EventId -eq '4624' -or $_.EventId -eq '4625' })) {
            $w = $null; try { $w = ([datetime]$r.TimestampUTC).ToUniversalTime() } catch { }
            [void]$logons.Add((New-Object PSObject -Property @{
                WhenUtc = $w; User = [string]$r.User; Ip = [string]$r.SourceIP; Type = [string]$r.LogonType
                Estacion = [string]$r.WorkstationName
                Result = $(if ($r.EventId -eq '4624') { 'Correcto' } else { 'FALLIDO' }); Source = ('Security ' + $r.EventId)
                Clase = (Get-LogonClass -User ([string]$r.User) -LogonType ([string]$r.LogonType))
            }))
        }
    } catch { }
    if (Test-Path -LiteralPath $rsCsv) {
        try {
            foreach ($r in @(Import-Csv -LiteralPath $rsCsv)) {
                $w = $null; try { $w = ([datetime]$r.TimestampUTC).ToUniversalTime() } catch { }
                if (-not $r.SourceIP -and -not $r.User) { continue }
                [void]$logons.Add((New-Object PSObject -Property @{
                    WhenUtc = $w; User = [string]$r.User; Ip = [string]$r.SourceIP; Type = '10'
                    Estacion = ''; Result = 'Sesion RDP'; Source = ('RDP ' + $r.EventId); Clase = 'Humano' }))
            }
        } catch { }
    }

    
    $byUser = @{}
    foreach ($e in $logons) {
        $u = if ($e.User) { $e.User } else { '(desconocido)' }
        if ($e.Clase -ne 'Humano') { continue }
        if (-not $byUser.ContainsKey($u)) { $byUser[$u] = New-Object PSObject -Property @{ User=$u; Correctos=0; Fallidos=0; IpsNoche=(New-Object System.Collections.Generic.HashSet[string]); EstNoche=(New-Object System.Collections.Generic.HashSet[string]); IpsAntes=(New-Object System.Collections.Generic.HashSet[string]); Tipos=(New-Object System.Collections.Generic.HashSet[string]); PrimeraUtc=$null; UltimaUtc=$null } }
        $m = $byUser[$u]
        if ($e.Result -eq 'FALLIDO') { $m.Fallidos++ } else { $m.Correctos++ }
        $inWin = ($e.WhenUtc -and $e.WhenUtc -ge $incSUtc -and $e.WhenUtc -le $incEUtc)
        if ($inWin) { if ($e.Ip) { [void]$m.IpsNoche.Add($e.Ip) }; if ($e.Estacion) { [void]$m.EstNoche.Add($e.Estacion) } }
        elseif ($e.Ip) { [void]$m.IpsAntes.Add($e.Ip) }
        $tn = Get-LogonTypeName $e.Type; if ($tn) { [void]$m.Tipos.Add($tn) }
        if ($e.WhenUtc) { if (-not $m.PrimeraUtc -or $e.WhenUtc -lt $m.PrimeraUtc) { $m.PrimeraUtc = $e.WhenUtc }; if (-not $m.UltimaUtc -or $e.WhenUtc -gt $m.UltimaUtc) { $m.UltimaUtc = $e.WhenUtc } }
    }
    $mapRecs = @($byUser.Values | ForEach-Object {
        New-Object PSObject -Property @{
            Usuario=$_.User; IniciosCorrectos=$_.Correctos; IntentosFallidos=$_.Fallidos
            IpEsaNoche=(@($_.IpsNoche) -join ', '); EstacionEsaNoche=(@($_.EstNoche) -join ', '); IpHabitual=(@($_.IpsAntes) -join ', ')
            TiposDeInicio=(@($_.Tipos) -join '; ')
            PrimeraVezUTC=$(if($_.PrimeraUtc){$_.PrimeraUtc.ToString($script:TsFmt)}else{''})
            UltimaVezUTC=$(if($_.UltimaUtc){$_.UltimaUtc.ToString($script:TsFmt)}else{''})
        }
    })
    if ($mapRecs.Count -gt 0) { Export-ObjectData -Data $mapRecs -BaseName '53_logon_map' -Category 'LogonCorrelation' }

    
    $byIp = @{}
    foreach ($e in $logons) {
        if (-not $e.Ip -or $e.Ip -eq '-' -or $e.Ip -eq '::1' -or $e.Ip -eq '127.0.0.1') { continue }
        if (-not $byIp.ContainsKey($e.Ip)) { $byIp[$e.Ip] = New-Object System.Collections.ArrayList }
        [void]$byIp[$e.Ip].Add($e)
    }
    $ipRecs = New-Object System.Collections.ArrayList
    foreach ($ip in $byIp.Keys) {
        $ent = @($byIp[$ip])
        $during = @($ent | Where-Object { $_.WhenUtc -and $_.WhenUtc -ge $incSUtc -and $_.WhenUtc -le $incEUtc })
        $before = @($ent | Where-Object { $_.WhenUtc -and $_.WhenUtc -lt $incSUtc })
        
        $firstBefore = ($before | Where-Object { $_.WhenUtc } | Sort-Object WhenUtc | Select-Object -First 1).WhenUtc
        $lastBefore  = ($before | Where-Object { $_.WhenUtc } | Sort-Object WhenUtc | Select-Object -Last 1).WhenUtc
        $firstDuring = ($during | Where-Object { $_.WhenUtc } | Sort-Object WhenUtc | Select-Object -First 1).WhenUtc
        
        $spanDays = 0; if ($firstBefore -and $lastBefore) { $spanDays = [int]([math]::Round(($lastBefore - $firstBefore).TotalDays)) }
        
        $daysSincePrev = $null; if ($lastBefore) { $daysSincePrev = [int]([math]::Round(($incSUtc - $lastBefore).TotalDays)) }
        $usersF = @($during + $before | ForEach-Object { $_.User } | Where-Object { $_ } | Sort-Object -Unique)
        $stationsBefore = @($before | ForEach-Object { $_.Estacion } | Where-Object { $_ } | Sort-Object -Unique)
        $stationsDuring = @($during | ForEach-Object { $_.Estacion } | Where-Object { $_ } | Sort-Object -Unique)
        $stationsF = @($ent | ForEach-Object { $_.Estacion } | Where-Object { $_ } | Sort-Object -Unique)
        $isPriv = ($ip -match '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|fe80:|fc|fd)')
        $ipTipo = $(
            if ($ip -match '^(?i)LOCAL$|^-$|^::1$|^127\.') { 'Local (consola/loopback)' }
            elseif ($ip -match '^(?i)fe80:') { 'Privada (IPv6 enlace local)' }
            elseif ($isPriv) { 'Privada (interna)' }
            elseif ($ip -match '^\d+\.\d+\.\d+\.\d+$|^[0-9a-f:]+$') { 'Publica (Internet)' }
            else { 'No es una IP (nombre/marcador)' }
        )
        
        $verdict = $(
            if ($during.Count -gt 0 -and $before.Count -gt 0 -and $spanDays -ge 150) { 'CORRELACION FUERTE: misma IP en el periodo y ya usada >= 6 meses antes' }
            elseif ($during.Count -gt 0 -and $before.Count -gt 0) { 'ALTA: misma IP en el periodo y con anterioridad (' + $spanDays + ' dias de historico previo)' }
            elseif ($during.Count -gt 0 -and $before.Count -eq 0) { 'NUEVA: IP presente SOLO en el periodo (sin historico previo en los registros conservados; no implica anomalia si el historico es escaso)' }
            else { 'Solo historico (no aparece en la ventana del periodo)' }
        )
        [void]$ipRecs.Add((New-Object PSObject -Property @{
            IP=$ip; Tipo=$ipTipo
            VecesEnElAtaque=$during.Count; VecesAntes=$before.Count
            FirstSeenUTC=$(if($firstBefore){$firstBefore.ToString($script:TsFmt)}elseif($firstDuring){$firstDuring.ToString($script:TsFmt)}else{''})
            LastSeenBeforePeriodUTC=$(if($lastBefore){$lastBefore.ToString($script:TsFmt)}else{''})
            SeenInPeriod=$(if($during.Count -gt 0){'Si'}else{'No'})
            PrimeraVezUTC=$(if($firstBefore){$firstBefore.ToString($script:TsFmt)}elseif($firstDuring){$firstDuring.ToString($script:TsFmt)}else{''})
            UltimaVezUTC=$(($ent|Where-Object{$_.WhenUtc}|Sort-Object WhenUtc|Select-Object -Last 1).WhenUtc.ToString($script:TsFmt))
            DiasDeHistoricoPrevio=$spanDays
            DiasAntesDelAtaque=$daysSincePrev
            EstacionesPrevias=(@($stationsBefore) -join ', '); EstacionesEnPeriodo=(@($stationsDuring) -join ', ')
            Usuarios=(@($usersF) -join ', '); Estaciones=(@($stationsF) -join ', '); Correlacion=$verdict
        }))
    }
    $ipSorted = @($ipRecs | Sort-Object @{E={$_.Correlacion -like 'CORRELACION FUERTE*'};D=$true}, @{E={$_.Correlacion -like 'ALTA*'};D=$true}, @{E='VecesEnElAtaque';D=$true})
    if ($ipSorted.Count -gt 0) { Export-ObjectData -Data $ipSorted -BaseName '52_logon_ip_correlation' -Category 'LogonCorrelation' }

    
    $winLogons = @($logons | Where-Object { $_.WhenUtc -and $_.WhenUtc -ge $incSUtc -and $_.WhenUtc -le $incEUtc })
    $winRecs = @($winLogons | Sort-Object WhenUtc | ForEach-Object {
        New-Object PSObject -Property @{
            HoraLocal = $_.WhenUtc.ToLocalTime().ToString($script:TsFmt); HoraUTC = $_.WhenUtc.ToString($script:TsFmt)
            Usuario = $_.User; Resultado = $_.Result; IP = $_.Ip; Estacion = $_.Estacion
            Tipo = (Get-LogonTypeName $_.Type); Clase = $_.Clase; Fuente = $_.Source
        }
    })
    
    $winHuman = @($winRecs | Where-Object { $_.Clase -eq 'Humano' })
    $winOk = @($winHuman | Where-Object { $_.Resultado -ne 'FALLIDO' })
    $winFail = @($winHuman | Where-Object { $_.Resultado -eq 'FALLIDO' })
    $winNoise = @($winRecs | Where-Object { $_.Clase -ne 'Humano' })
    if ($winNoise.Count -gt 0) { Export-ObjectData -Data $winNoise -BaseName '57_logon_system_service_during_attack' -Category 'LogonCorrelation' }
    if ($winOk.Count -gt 0)   { Export-ObjectData -Data $winOk   -BaseName '54_logon_ok_during_attack' -Category 'LogonCorrelation' }
    if ($winFail.Count -gt 0) { Export-ObjectData -Data $winFail -BaseName '55_logon_fail_during_attack' -Category 'LogonCorrelation' }
    $stCounts = @{}
    foreach ($e in $winLogons) {
        $st = $(if ($e.Estacion) { $e.Estacion } else { '(sin estacion)' })
        if (-not $stCounts.ContainsKey($st)) { $stCounts[$st] = New-Object PSObject -Property @{ Estacion=$st; Intentos=0; Correctos=0; Fallidos=0; Usuarios=(New-Object System.Collections.Generic.HashSet[string]) } }
        $c = $stCounts[$st]; $c.Intentos++
        if ($e.Result -eq 'FALLIDO') { $c.Fallidos++ } else { $c.Correctos++ }
        if ($e.User) { [void]$c.Usuarios.Add($e.User) }
    }
    $stRecs = @($stCounts.Values | Sort-Object Intentos -Descending | ForEach-Object { New-Object PSObject -Property @{ Estacion=$_.Estacion; Intentos=$_.Intentos; Correctos=$_.Correctos; Fallidos=$_.Fallidos; Usuarios=(@($_.Usuarios) -join ', ') } })
    if ($stRecs.Count -gt 0) { Export-ObjectData -Data $stRecs -BaseName '56_station_counts_during_attack' -Category 'LogonCorrelation' }
    Write-ForensicLog -Message ('LogonCorrelation (ventana): {0} accesos correctos, {1} intentos fallidos, {2} estaciones de origen.' -f $winOk.Count, $winFail.Count, $stRecs.Count)

    $strong = @($ipSorted | Where-Object { $_.Correlacion -like 'CORRELACION FUERTE*' -or $_.Correlacion -like 'ALTA*' })
    Write-ForensicLog -Message ('LogonCorrelation: {0} IPs analizadas; {1} con correlacion antes/durante; {2} usuarios en el mapa.' -f $ipSorted.Count, $strong.Count, $mapRecs.Count)
    if (@($ipSorted | Where-Object { $_.VecesAntes -eq 0 -and $_.VecesEnElAtaque -gt 0 }).Count -eq $ipSorted.Count -and $ipSorted.Count -gt 0) {
        Register-MissingEvidence -Evidence 'Historico de IP > 6 meses' -Reason 'No hay eventos anteriores a la ventana en los registros conservados (Security rota). Para comparar con 6 meses atras se requieren registros con mayor retencion o instantaneas/imagen que los conserven.'
    }
    Write-ForensicLog -Message 'Modulo LogonCorrelation completado.'
}








function Copy-RawNtfsMetafile {
    

    param([string]$MetaName, [string]$Dest)
    
    $vol = $(if ($env:SystemDrive) { $env:SystemDrive } else { 'C:' })
    $src = ($vol + '\' + $MetaName)
    $ok = $false
    try {
        $r = Copy-EvidenceFile -SourcePath $src -DestinationPath $Dest -Category 'EvidencePreservation' -Notes ('Metaarchivo NTFS ' + $MetaName + ' (analisis offline con herramientas MFT)')
        if ($r) { $ok = $true }
    } catch { }
    return $ok
}

function Invoke-ModuleEvidencePreservation {
    Write-ForensicLog -Message '--- MODULO EvidencePreservation ---'
    $destDir = Join-Path $script:Paths.RawFS 'PreservedArtifacts'
    if (-not (Test-Path -LiteralPath $destDir)) { try { New-Item -ItemType Directory -Path $destDir -Force | Out-Null } catch { } }

    
    Register-Source 'Verificacion de sincronizacion horaria del sistema'
    $tzDisplay = ''; $tzOffMin = ''
    try { $tzDisplay = [System.TimeZoneInfo]::Local.DisplayName } catch { }
    try { $tzOffMin = [System.TimeZoneInfo]::Local.GetUtcOffset((Get-Date)).TotalMinutes } catch { }
    $timeInfo = New-Object PSObject -Property @{
        HoraLocalSistema = (Get-Date).ToString($script:TsFmt)
        HoraUTCSistema   = (Get-Date).ToUniversalTime().ToString($script:TsFmt)
        ZonaHoraria      = $tzDisplay
        DesfaseUTCMin    = $tzOffMin
        FuenteHoraNTP    = ''
        DesfaseVsNTPSeg  = ''
        Nota             = 'Toda marca temporal del informe depende del reloj de este equipo. Verifiquese el desfase.'
    }
    
    try {
        $st = & $env:ComSpec /c 'w32tm /query /status 2>&1'
        if ($st) { $timeInfo.FuenteHoraNTP = (($st | Where-Object { $_ -match '(?i)fuente|source' } | Select-Object -First 1)) }
        $strip = & $env:ComSpec /c 'w32tm /stripchart /computer:time.windows.com /samples:1 /dataonly 2>&1'
        if ($strip) {
            $m = [regex]::Match(($strip -join ' '), '([-+]?\d+[\.,]\d+)s')
            if ($m.Success) { $timeInfo.DesfaseVsNTPSeg = $m.Groups[1].Value }
        }
    } catch { }
    Export-ObjectData -Data @($timeInfo) -BaseName '99_time_sync' -Category 'EvidencePreservation'
    Write-ForensicLog -Message ('Sincronizacion horaria registrada (desfase UTC {0} min).' -f $timeInfo.DesfaseUTCMin)

    
    if ($script:IsAdmin) {
        Register-Source 'Metaarchivos NTFS ($MFT, $LogFile, $UsnJrnl)'
        $any = $false
        foreach ($meta in @('$MFT', '$LogFile', '$Extend\$UsnJrnl:$J')) {
            $leaf = ($meta -replace '[\\:$]', '_')
            if (Copy-RawNtfsMetafile -MetaName $meta -Dest (Join-Path $destDir $leaf)) { $any = $true }
        }
        if (-not $any) { Register-MissingEvidence -Evidence 'Metaarchivos NTFS en crudo' -Reason 'No se pudieron copiar en vivo (bloqueados). Se obtienen de una instantanea VSS montada o de imagen de disco.' }
    } else {
        Register-MissingEvidence -Evidence 'Metaarchivos NTFS ($MFT/$LogFile/$UsnJrnl)' -Reason 'Requiere administrador'
    }

    
    Register-Source 'Logs de bases de datos (SQL Server / MySQL / PostgreSQL)'
    $dbCandidates = New-Object System.Collections.ArrayList
    foreach ($pair in @(@($env:ProgramFiles,'Microsoft SQL Server'), @(${env:ProgramFiles(x86)},'Microsoft SQL Server'), @($env:ProgramData,'MySQL'), @($env:ProgramFiles,'MySQL'), @($env:ProgramFiles,'PostgreSQL'))) {
        if ($pair[0]) { [void]$dbCandidates.Add((Join-Path $pair[0] $pair[1])) }
    }
    [void]$dbCandidates.Add('C:\xampp\mysql\data')
    $dbFound = 0
    foreach ($base in $dbCandidates) {
        if (-not $base -or -not (Test-Path -LiteralPath $base)) { continue }
        try {
            $logs = @(Get-ChildItem -LiteralPath $base -Recurse -File -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match '(?i)^ERRORLOG|\.err$|mysql.*\.log$|\.log$|postgresql.*\.log$|default.*\.trc$' } |
                Select-Object -First 200)
            foreach ($lf in $logs) {
                $rel = ($lf.FullName -replace '[:\\]', '_')
                if (Copy-EvidenceFile -SourcePath $lf.FullName -DestinationPath (Join-Path (Join-Path $destDir 'DB_Logs') $rel) -Category 'EvidencePreservation' -Notes 'Log de base de datos (acredita operaciones y borrados)') { $dbFound++ }
            }
        } catch { }
    }
    if ($dbFound -gt 0) { Write-ForensicLog -Message ('Logs de BBDD preservados: {0} ficheros (revisar DROP/DELETE y su autor).' -f $dbFound) }
    else { Register-MissingEvidence -Evidence 'Logs de bases de datos' -Reason 'No se localizaron instalaciones de SQL Server/MySQL/PostgreSQL en rutas estandar (o sin logs accesibles)' -Status 'NOT_INSTALLED' }

    
    Register-Source 'Log del firewall de Windows'
    $sysRoot = Get-WinEnvPath SystemRoot
    $fwLog = $(if ($sysRoot) { Join-Path $sysRoot 'System32\LogFiles\Firewall\pfirewall.log' } else { $null })
    if ($fwLog -and (Test-Path -LiteralPath $fwLog)) {
        Copy-EvidenceFile -SourcePath $fwLog -DestinationPath (Join-Path $destDir 'pfirewall.log') -Category 'EvidencePreservation' -Notes 'Log del firewall de Windows (conexiones permitidas/bloqueadas con IP y hora)' | Out-Null
        Write-ForensicLog -Message 'Log del firewall de Windows preservado.'
    } else {
        Register-MissingEvidence -Evidence 'Log del firewall de Windows' -Reason 'Registro de firewall no habilitado (pfirewall.log no existe). La IP real tras una VPN se obtiene del firewall/router perimetral, cuyos logs deben solicitarse aparte.'
    }

    
    Register-Source 'Captura de memoria RAM (volatil)'
    $ramTool = $null
    foreach ($t in @('winpmem.exe', 'winpmem_mini_x64.exe', 'DumpIt.exe', 'magnet.exe')) {
        $baseDir = $null; try { $baseDir = Split-Path -Parent $PSCommandPath } catch { }
        if ($baseDir) { $cand = Join-Path $baseDir $t; if (Test-Path -LiteralPath $cand) { $ramTool = $cand; break } }
        $cwd = (Get-Location).Path
        if ($cwd) { $cand2 = Join-Path $cwd $t; if (Test-Path -LiteralPath $cand2) { $ramTool = $cand2; break } }
    }
    if ($ramTool -and $script:IsAdmin) {
        $ramOut = Join-Path $destDir 'memoria_ram.raw'
        try {
            Write-ForensicLog -Message ('Capturando RAM con {0} (puede tardar; orden de volatilidad RFC 3227)...' -f (Split-Path $ramTool -Leaf))
            & $ramTool $ramOut 2>&1 | Out-Null
            if (Test-Path -LiteralPath $ramOut) {
                $h = Get-EvidenceFileHash -Path $ramOut -Algorithm SHA256
                Register-Evidence -Path $ramOut -Category 'EvidencePreservation' -SourceDescription ('Volcado de RAM (' + (Split-Path $ramTool -Leaf) + ')') -Notes ('SHA256=' + $h)
                Write-ForensicLog -Message ('RAM capturada: {0} (SHA256={1}).' -f $ramOut, $h)
            }
        } catch { Write-ForensicLog -Level WARN -Message ('Captura de RAM fallo: {0}' -f $_.Exception.Message) }
    } else {
        Register-MissingEvidence -Evidence 'Captura de memoria RAM' -Reason 'No se hallo herramienta de volcado (winpmem/DumpIt) junto al script, o sin admin. La RAM contiene procesos, conexiones y claves que se pierden al apagar; para capturarla, coloque winpmem.exe junto a este script antes de ejecutar. Debe hacerse ANTES de apagar el equipo.' -Status 'NOT_INSTALLED'
    }

    Write-ForensicLog -Message 'Modulo EvidencePreservation completado.'
}














function Read-EvtxSecurityRecords {
    
    param([string]$EvtxPath, [string]$Origin)
    $out = New-Object System.Collections.ArrayList
    if (-not (Test-Path -LiteralPath $EvtxPath)) { return $out }
    if (-not (Test-CommandAvailable 'Get-WinEvent')) { return $out }
    $ids = @(4624, 4625, 4634, 4647, 4648, 4672, 4720, 4722, 4723, 4724, 4725, 4726, 4732, 4728, 4740, 1102)
    
    $chunks = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt $ids.Count; $i += 22) { [void]$chunks.Add(@($ids[$i..([math]::Min($i + 21, $ids.Count - 1))])) }
    foreach ($chunk in $chunks) {
        try {
            $evs = @(Get-WinEvent -Path $EvtxPath -FilterHashtable @{ Id = $chunk } -ErrorAction Stop)
            foreach ($e in $evs) {
                $rec = Convert-EventToNormalizedRecord -Event $e -ChannelTag ('VSS:' + (Split-Path $EvtxPath -Leaf))
                $rec | Add-Member -NotePropertyName 'OrigenHistorico' -NotePropertyValue $Origin -Force
                [void]$out.Add($rec)
            }
        } catch {
            if ($_.Exception.Message -notmatch 'No events|No se encontr') {
                Write-ForensicLog -Level DEBUG -Message ('Read-EvtxSecurityRecords: {0} en {1}' -f $_.Exception.Message, $EvtxPath)
            }
        }
    }
    return $out
}

function Invoke-ModuleHistoricalLogs {
    Write-ForensicLog -Message '--- MODULO HistoricalLogs (recuperacion desde VSS / evtx archivados) ---'
    Register-Source 'Eventos historicos: Security.evtx dentro de instantaneas VSS y .evtx archivados'
    if (-not $script:IsAdmin) {
        Register-MissingEvidence -Evidence 'Eventos historicos (VSS/archivados)' -Reason 'Requiere administrador para acceder a las instantaneas de volumen'
        return
    }

    $histDir = Join-Path $script:Paths.RawEvt 'Historical'
    if (-not (Test-Path -LiteralPath $histDir)) { try { New-Item -ItemType Directory -Path $histDir -Force | Out-Null } catch { } }
    $sysRoot = Get-WinEnvPath SystemRoot
    if (-not $sysRoot) { $sysRoot = 'C:\Windows' }
    $relLogs = 'System32\winevt\Logs'
    $collected = New-Object System.Collections.ArrayList   
    $sources = New-Object System.Collections.ArrayList

    
    $vssRaw = $null
    try { $vssRaw = & $env:ComSpec /c 'vssadmin list shadows 2>&1' } catch { }
    $shadows = @()
    if ($vssRaw) { $shadows = @(ConvertFrom-VssList -Lines ([string[]]$vssRaw)) }
    if ($shadows.Count -eq 0) {
        Register-MissingEvidence -Evidence 'Security.evtx historico (VSS)' -Reason 'No hay instantaneas de volumen. Sin VSS, el Security anterior a la retencion actual solo se recupera de imagen de disco o del firewall.'
    }
    $idx = 0
    foreach ($sh in $shadows) {
        $idx++
        if (-not $sh.Device) { continue }
        $tag = ('VSS{0}_{1}' -f $idx, (($sh.CreationLocal -replace '[^0-9]', '')))
        foreach ($ln in @('Security', 'System')) {
            $snapEvtx = ($sh.Device.TrimEnd('\') + '\' + $relLogs + '\' + $ln + '.evtx')
            $dest = Join-Path $histDir ($ln + '_' + $tag + '.evtx')
            try {
                Copy-Item -LiteralPath $snapEvtx -Destination $dest -Force -ErrorAction Stop
                Register-Evidence -Path $dest -Category 'HistoricalLogs' -SourceDescription ($ln + '.evtx dentro de la instantanea ' + $sh.ShadowId + ' del ' + $sh.CreationLocal) -Notes 'Log de eventos de fecha anterior recuperado de instantanea VSS'
                if ($ln -eq 'Security') { [void]$collected.Add($dest); [void]$sources.Add(('Instantanea VSS del ' + $sh.CreationLocal)) }
            } catch {
                Write-ForensicLog -Level DEBUG -Message ('No se pudo copiar {0} de la instantanea {1}: {2}' -f $ln, $idx, $_.Exception.Message)
            }
        }
    }

    
    $liveLogs = Join-Path $sysRoot $relLogs
    if (Test-Path -LiteralPath $liveLogs) {
        try {
            $archived = @(Get-ChildItem -LiteralPath $liveLogs -Filter 'Archive-Security-*.evtx' -File -Force -ErrorAction SilentlyContinue)
            foreach ($af in $archived) {
                $dest = Join-Path $histDir $af.Name
                if (Copy-EvidenceFile -SourcePath $af.FullName -DestinationPath $dest -Category 'HistoricalLogs' -Notes 'Security.evtx archivado (rotacion de Windows)') {
                    [void]$collected.Add($dest); [void]$sources.Add(('Archivo ' + $af.Name))
                }
            }
        } catch { }
    }

    if ($collected.Count -eq 0) {
        Write-ForensicLog -Message 'HistoricalLogs: no se recuperaron .evtx historicos (sin VSS utiles ni archivados).'
        Write-ForensicLog -Message 'Modulo HistoricalLogs completado.'
        return
    }

    
    $liveKeys = @{}
    $liveCsv = Join-Path $script:Paths.ParsedCSV '20_security_events.csv'
    if (Test-Path -LiteralPath $liveCsv) {
        try { foreach ($r in @(Import-Csv -LiteralPath $liveCsv)) { $liveKeys[('{0}|{1}|{2}|{3}' -f $r.TimestampUTC, $r.EventId, $r.User, $r.SourceIP)] = $true } } catch { }
    }
    $histRecs = New-Object System.Collections.ArrayList
    $histKeys = @{}
    foreach ($i in 0..($collected.Count - 1)) {
        $recs = Read-EvtxSecurityRecords -EvtxPath $collected[$i] -Origin $sources[$i]
        foreach ($r in $recs) {
            $key = ('{0}|{1}|{2}|{3}' -f $r.TimestampUTC, $r.EventId, $r.User, $r.SourceIP)
            if ($liveKeys.ContainsKey($key)) { continue }   
            if ($histKeys.ContainsKey($key)) { continue }    
            $histKeys[$key] = $true
            [void]$histRecs.Add($r)
        }
    }

    if ($histRecs.Count -gt 0) {
        Export-ObjectData -Data @($histRecs | Sort-Object TimestampUTC) -BaseName '20b_security_events_historical' -Category 'HistoricalLogs'
        $times = @($histRecs | ForEach-Object { $_.TimestampUTC } | Where-Object { $_ } | Sort-Object)
        $minH = $times | Select-Object -First 1; $maxH = $times | Select-Object -Last 1
        $nLogon = @($histRecs | Where-Object { $_.EventId -eq 4624 -or $_.EventId -eq 4625 }).Count
        Write-ForensicLog -Message ('HistoricalLogs: {0} eventos historicos NUEVOS recuperados (no estaban en el log vivo), de los cuales {1} inicios de sesion. Cobertura historica: {2} a {3}.' -f $histRecs.Count, $nLogon, $minH, $maxH)
        Write-ForensicLog -Message 'IMPORTANTE: estos eventos amplian la ventana temporal mas alla de la retencion del log vivo (recuperados de VSS/archivados). Revisar 20b_security_events_historical.csv para los inicios de sesion de fechas ya rotadas.'
    } else {
        Register-MissingEvidence -Evidence 'Eventos historicos nuevos' -Reason 'Los .evtx recuperados no aportaron eventos anteriores a los ya presentes en vivo (misma cobertura, o instantaneas recientes)' -Status 'EMPTY'
    }
    Write-ForensicLog -Message 'Modulo HistoricalLogs completado.'
}

function Invoke-ModuleSecurityTools {
    if (-not (Test-ModuleSelected 'SecurityTools')) { return }
    Write-ForensicLog -Message '--- MODULO SecurityTools ---'
    Register-Source 'Get-MpComputerStatus / logs de Defender y Firewall'

    if (Test-CommandAvailable 'Get-MpComputerStatus') {
        try {
            $mp = Get-MpComputerStatus -ErrorAction Stop
            $mpObj = New-Object PSObject -Property @{
                AMServiceEnabled = $mp.AMServiceEnabled; RealTimeProtectionEnabled = $mp.RealTimeProtectionEnabled
                AntivirusEnabled = $mp.AntivirusEnabled; AntivirusSignatureLastUpdated = if ($mp.AntivirusSignatureLastUpdated) { $mp.AntivirusSignatureLastUpdated.ToString($script:TsFmt) } else { $null }
                IsTamperProtected = $mp.IsTamperProtected; CollectedUTC = Get-NowUtcString
            }
            Export-ObjectData -Data $mpObj -BaseName '80_defender_status' -Category 'SecurityTools'
        } catch { Register-MissingEvidence -Evidence 'Get-MpComputerStatus' -Reason $_.Exception.Message }
        try {
            $prefs = Get-MpPreference -ErrorAction Stop
            $exObj = New-Object PSObject -Property @{
                ExclusionPath = ($prefs.ExclusionPath -join '; ')
                ExclusionProcess = ($prefs.ExclusionProcess -join '; ')
                ExclusionExtension = ($prefs.ExclusionExtension -join '; ')
                DisableRealtimeMonitoring = $prefs.DisableRealtimeMonitoring
                Note = 'Exclusiones amplias o recientes pueden indicar preparacion de evasion (indicador)'
                CollectedUTC = Get-NowUtcString
            }
            Export-ObjectData -Data $exObj -BaseName '81_defender_exclusions' -Category 'SecurityTools'
        } catch { }
    } else {
        Register-MissingEvidence -Evidence 'Modulo Defender (Get-MpComputerStatus)' -Reason 'Cmdlet no disponible (SO antiguo o AV de terceros)'
    }

    
    $fwLog = Join-Path (Get-WinEnvPath SystemRoot) 'System32\LogFiles\Firewall\pfirewall.log'
    Copy-EvidenceFile -SourcePath $fwLog -DestinationPath (Join-Path $script:Paths.RawSec 'pfirewall.log') -Category 'SecurityTools' -Notes 'Log de firewall (solo si el registro esta habilitado por politica)' | Out-Null

    
    $defSupport = Join-Path (Get-WinEnvPath ProgramData) 'Microsoft\Windows Defender\Support'
    if (Test-Path -LiteralPath $defSupport) {
        foreach ($f in @(Get-ChildItem -LiteralPath $defSupport -Filter 'MPLog*.log' -Force -ErrorAction SilentlyContinue)) {
            Copy-EvidenceFile -SourcePath $f.FullName -DestinationPath (Join-Path $script:Paths.RawSec $f.Name) -Category 'SecurityTools' -Notes 'MPLog de Defender' | Out-Null
        }
    }
    Write-ForensicLog -Message 'Modulo SecurityTools completado.'
}




function Invoke-ModuleAITools {
    if (-not (Test-ModuleSelected 'AITools')) { return }
    Write-ForensicLog -Message '--- MODULO AITools ---'
    Register-Source 'Deteccion de clientes/agentes de IA (Claude, Claude Code, ChatGPT, Copilot, MCP, extensiones IDE)'
    
    
    
    $aiDir = Join-Path $script:Paths.RawFS 'AITools'
    $detections = New-Object System.Collections.ArrayList
    $profiles = Get-CimOrWmi -ClassName 'Win32_UserProfile'

    foreach ($p in @($profiles)) {
        if ($null -eq $p -or $p.Special -or -not $p.LocalPath) { continue }
        $lp = $p.LocalPath
        $sidSafe = ($p.SID -replace '[^A-Za-z0-9-]','_')
        $targets = @(
            @{ Name='ClaudeDesktop';    Path='AppData\Roaming\Claude';                 CollectLogs=$true;  Note='Cliente de escritorio Claude (config y logs; puede incluir MCP)' }
            @{ Name='ClaudeCode';       Path='.claude';                                CollectLogs=$true;  Note='Claude Code: settings, historial de proyectos y sesiones' }
            @{ Name='ClaudeCode_json';  Path='.claude.json';                           CollectLogs=$true;  Note='Configuracion global Claude Code' }
            @{ Name='ChatGPT_Desktop';  Path='AppData\Local\Programs\ChatGPT';         CollectLogs=$false; Note='Cliente ChatGPT (presencia)' }
            @{ Name='Cursor';           Path='AppData\Roaming\Cursor';                 CollectLogs=$false; Note='IDE Cursor con agente' }
            @{ Name='GitHubCopilot_VSCode'; Path='.vscode\extensions';                 CollectLogs=$false; Note='Extensiones VS Code (buscar github.copilot*)' }
            @{ Name='Codeium_Windsurf'; Path='AppData\Roaming\Windsurf';               CollectLogs=$false; Note='IDE Windsurf' }
            @{ Name='OpenAI_Codex_CLI'; Path='.codex';                                 CollectLogs=$true;  Note='Codex CLI: sesiones' }
            @{ Name='Gemini_CLI';       Path='.gemini';                                CollectLogs=$true;  Note='Gemini CLI' }
            @{ Name='MCP_generic';      Path='AppData\Roaming\Claude\claude_desktop_config.json'; CollectLogs=$true; Note='Config MCP: servidores con acceso a recursos locales' }
        )
        foreach ($t in $targets) {
            $full = Join-Path $lp $t.Path
            $exists = Test-Path -LiteralPath $full
            if (-not $exists) { continue }   
            
            
            [void]$detections.Add((New-Object PSObject -Property @{
                ProfileSID = $p.SID; Producto = $t.Name; Tipo = 'Aplicacion IA instalada'
                EvidenceSource = 'Directorio de cliente/configuracion en el perfil de usuario'
                DetectionReason = ('Existe la ruta caracteristica: {0}' -f $t.Path)
                Path = $full; Confidence = 'Alta'
                Note = $t.Note; CollectedUTC = Get-NowUtcString
            }))
            if ($exists -and $t.CollectLogs) {
                $item = Get-Item -LiteralPath $full -Force -ErrorAction SilentlyContinue
                if ($item -and -not $item.PSIsContainer) {
                    Copy-EvidenceFile -SourcePath $full -DestinationPath (Join-Path (Join-Path $aiDir ($t.Name + '_' + $sidSafe)) $item.Name) -Category 'AITools' -Notes $t.Note | Out-Null
                } elseif ($item) {
                    
                    foreach ($f in @(Get-ChildItem -LiteralPath $full -Recurse -Force -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in '.json','.jsonl','.log','.txt','.yaml','.yml','.toml' -and $_.Length -lt 50MB })) {
                        $rel = $f.FullName.Substring($full.Length).TrimStart('\')
                        Copy-EvidenceFile -SourcePath $f.FullName -DestinationPath (Join-Path (Join-Path $aiDir ($t.Name + '_' + $sidSafe)) $rel) -Category 'AITools' -Notes $t.Note | Out-Null
                    }
                }
            }
        }
        
        $extDir = Join-Path $lp '.vscode\extensions'
        if (Test-Path -LiteralPath $extDir) {
            foreach ($d in @(Get-ChildItem -LiteralPath $extDir -Directory -Force -ErrorAction SilentlyContinue)) {
                if ($d.Name -match 'copilot|claude|codeium|tabnine|continue|cursor|anthropic|openai') {
                    [void]$detections.Add((New-Object PSObject -Property @{
                        ProfileSID = $p.SID; Producto = ('VSCodeExt:' + $d.Name); Tipo = 'Extension de navegador/IDE relacionada con IA'
                        EvidenceSource = 'Directorio de extension de VS Code'
                        DetectionReason = ('Nombre de extension coincide con proveedor de IA: {0}' -f $d.Name)
                        Path = $d.FullName; Confidence = 'Media'
                        Note = 'Extension IDE con capacidad potencial de ejecucion asistida (instalada; uso no acreditado)'; CollectedUTC = Get-NowUtcString
                    }))
                }
            }
        }
    }
    
    $aiWebCsv = Join-Path $script:Paths.ParsedCSV '46_ai_web_usage.csv'
    if (Test-Path -LiteralPath $aiWebCsv) {
        try {
            foreach ($r in @(Import-Csv -LiteralPath $aiWebCsv)) {
                $hasDate = [bool]$r.TimestampUTC
                [void]$detections.Add((New-Object PSObject -Property @{
                    ProfileSID = $null; Producto = ([string]$r.Servicio); Tipo = 'Servicio de IA usado por navegador'
                    EvidenceSource = ('Historial de ' + [string]$r.Browser + $(if ($hasDate) { ' (visita con fecha)' } else { ' (URL sin fecha)' }))
                    DetectionReason = ('URL de servicio de IA en el historial: ' + [string]$r.Url)
                    Path = ([string]$r.Url); TimestampUTC = ([string]$r.TimestampUTC)
                    Confidence = $(if ($hasDate) { 'Alta' } else { 'Media' })
                    Note = 'Acceso a servicio de IA por web. Acredita acceso desde la cuenta; la autoria personal requiere indicios adicionales.'; CollectedUTC = Get-NowUtcString
                }))
            }
        } catch { }
    }
    
    $confOrder = @{ 'Alta'=0; 'Media'=1; 'Baja'=2 }
    $detOrdered = @($detections | Sort-Object @{E={ $o = $confOrder[[string]$_.Confidence]; if ($null -eq $o) { 3 } else { $o } }}, Tipo)
    Export-ObjectData -Data $detOrdered -BaseName '90_ai_tools_detection' -Category 'AITools'
    $nHigh = @($detections | Where-Object { $_.Confidence -eq 'Alta' }).Count
    Write-ForensicLog -Message ('Modulo AITools completado: {0} detecciones ({1} de confianza Alta). Recuerde: presencia != uso != autoria.' -f $detections.Count, $nHigh)
}




function Build-GlobalTimeline {
    






    Write-ForensicLog -Message '--- TIMELINE GLOBAL ---'
    $csvDir = $script:Paths.ParsedCSV
    $host0 = $script:ComputerName
    $tl = New-Object System.Collections.ArrayList
    $add = {
        param($tsUtc,$cat,$action,$user,$ip,$proc,$obj,$eid,$src,$conf)
        if (-not $tsUtc) { return }
        
        $tsClean = [string]$tsUtc
        $local = $null
        try { $dt = [datetime]::Parse($tsClean).ToUniversalTime(); $tsClean = $dt.ToString($script:TsFmt); $local = ConvertTo-MadridTimeString $dt } catch { }
        $exam = ''
        try {
            $exSince = $(if ($ExaminerSince -ne [datetime]::MinValue) { $ExaminerSince.ToUniversalTime() } else { $script:StartUtc })
            if ($exSince -and $dt -and $dt -ge $exSince) { $exam = 'ACTIVIDAD DEL EXAMINADOR (posterior al inicio de la intervencion pericial)' }
        } catch { }
        [void]$tl.Add((New-Object PSObject -Property @{
            TimestampUTC=$tsClean; TimestampLocal=$local; Category=$cat; Action=$action
            User=$user; Host=$host0; SourceIP=$ip; Process=$proc; Object=$obj
            EventID=$eid; EvidenceSource=$src; Confidence=$conf; Nota=$exam
        }))
    }
    $readCsv = {
        param($name)
        $f = Join-Path $csvDir ($name + '.csv')
        if (Test-Path -LiteralPath $f) { try { return @(Import-Csv -LiteralPath $f) } catch { return @() } }
        return @()
    }

    
    foreach ($r in (& $readCsv '20_security_events')) {
        $eid = [string]$r.EventId
        switch ($eid) {
            '4624' { & $add $r.TimestampUTC 'Logon' 'Inicio de sesion correcto' $r.User $r.SourceIP $r.ProcessName $r.WorkstationName $eid 'Security 4624' 'Alta' }
            '4625' { & $add $r.TimestampUTC 'Logon' ('Intento fallido: ' + [string]$r.FailureReason) $r.User $r.SourceIP $r.ProcessName $r.WorkstationName $eid 'Security 4625' 'Alta' }
            '4634' { & $add $r.TimestampUTC 'Logon' 'Cierre de sesion' $r.User $r.SourceIP $null $null $eid 'Security 4634' 'Alta' }
            '4688' { & $add $r.TimestampUTC 'Proceso' 'Creacion de proceso' $r.User $null $r.ProcessName $r.CommandLine $eid 'Security 4688' 'Alta' }
            '4720' { & $add $r.TimestampUTC 'Cuenta' 'Creacion de cuenta' $r.User $r.SourceIP $null $r.User $eid 'Security 4720' 'Alta' }
            '4724' { & $add $r.TimestampUTC 'Contrasena' 'Restablecimiento de contrasena' $r.User $r.SourceIP $null $r.User $eid 'Security 4724' 'Alta' }
            '4726' { & $add $r.TimestampUTC 'Cuenta' 'Borrado de cuenta' $r.User $r.SourceIP $null $r.User $eid 'Security 4726' 'Alta' }
            '1102' { & $add $r.TimestampUTC 'Antiforensia' 'Borrado del registro de Seguridad' $r.User $r.SourceIP $null 'Security.evtx' $eid 'Security 1102' 'Alta' }
        }
    }
    
    foreach ($r in (& $readCsv '82_password_account_events')) {
        & $add $r.TimestampUTC 'Contrasena' ([string]$r.Action) $r.ActorUser $r.SourceIP $null $r.TargetUser $r.EventId 'Security (cuenta)' 'Alta'
    }
    foreach ($r in (& $readCsv '85_password_group_commands')) {
        & $add $r.TimestampUTC 'Contrasena' 'Comando de gestion de contrasena/grupo' $r.UsuarioObjetivo $null $null ([string]$r.Comando) $null ([string]$r.Fuente) 'Media'
    }
    
    foreach ($r in (& $readCsv '29_rdp_session_timeline')) {
        & $add $r.InicioUTC 'RDP' ('Sesion RDP: ' + [string]$r.Conexion) $r.Usuario $r.IpOrigen $null ('SessionId ' + [string]$r.SessionId) $null 'RDP (reconstruido)' 'Alta'
    }
    
    foreach ($r in (& $readCsv '47_browser_history_timeline')) {
        & $add $r.TimestampUTC 'Navegacion' ('Visita web (' + [string]$r.Category + ')') $r.User $null $r.Browser ([string]$r.Url) $null ([string]$r.EvidenceSource) 'Alta'
    }
    foreach ($r in (& $readCsv '48_browser_downloads')) {
        & $add $r.StartTimeUTC 'Descarga' 'Descarga de archivo' $r.User $null $r.Browser ([string]$r.DownloadPath) $null 'Historial navegador' 'Alta'
    }
    
    foreach ($r in (& $readCsv '30_userassist')) {
        & $add $r.LastRunUTC 'Ejecucion' 'Ultima ejecucion (UserAssist)' $r.User $null ([string]$r.Program) $null $null 'UserAssist' 'Alta'
    }
    foreach ($r in (& $readCsv '43_program_execution_bam')) {
        & $add $r.UltimaVezUTC 'Ejecucion' 'Ultima ejecucion (BAM/DAM)' $r.Usuario $null ([string]$r.Programa) $null $null 'BAM/DAM' 'Alta'
    }
    
    foreach ($r in (& $readCsv '70_services')) {
        if ($r.InstaladoUTC) { & $add $r.InstaladoUTC 'Persistencia' 'Instalacion de servicio' $r.StartName $null ([string]$r.PathName) ([string]$r.Name) $r.InstalacionEventId 'System 7045 / Security 4697' 'Alta' }
    }
    foreach ($r in (& $readCsv '98_vss_snapshots')) {
        if ($r.CreationLocal) { & $add $r.CreationLocal 'VSS' 'Creacion de instantanea de volumen' $null $null $null ([string]$r.ShadowId) $null 'Win32_ShadowCopy' 'Media' }
    }
    
    foreach ($r in (& $readCsv '44_usb_devices')) {
        if ($r.FirstConnectedUTC) { & $add $r.FirstConnectedUTC 'USB' 'Conexion de dispositivo USB' $null $null $null ([string]$r.FriendlyName) $null 'Registro USBSTOR' 'Media' }
    }
    foreach ($r in (& $readCsv '96_deleted_files_timeline')) {
        
        
        $isWeakRef = ([string]$r.Event -match '(?i)referencia a archivo ausente')
        if ($isWeakRef) {
            $inP = $false
            try { $dtR = [datetime]::Parse([string]$r.TimestampUTC).ToUniversalTime(); $inP = ($script:IncidentStartUtc -and $script:IncidentEndUtc -and $dtR -ge $script:IncidentStartUtc -and $dtR -le $script:IncidentEndUtc) } catch { }
            if (-not $inP) { continue }
        }
        & $add $r.TimestampUTC 'Borrado' ([string]$r.Event) $r.User $null $null ([string]$r.Path) $null ([string]$r.Source) ([string]$r.Confidence)
    }
    
    foreach ($r in (& $readCsv '81_defender_exclusions')) {
        if ($r.CollectedUTC) { & $add $r.CollectedUTC 'Defender' 'Exclusion configurada (estado)' $null $null $null ([string]$r.ExclusionPath) $null 'Get-MpPreference' 'Media' }
    }

    if ($tl.Count -gt 0) {
        $sorted = @($tl | Sort-Object TimestampUTC)
        Export-ObjectData -Data $sorted -BaseName '00_global_timeline' -Category 'Timeline'
        Write-ForensicLog -Message ('Timeline global: {0} eventos datados unificados.' -f $tl.Count)
    } else {
        Write-ForensicLog -Level WARN -Message 'Timeline global: sin eventos datados (en vivo sin Get-WinEvent la mayoria de fuentes no producen fechas).'
    }
}

function Export-CommandAndErrorLogs {
    $cmdCsv = Join-Path $script:Paths.AcqLogs ('commands_{0}.csv' -f $script:AcquisitionId)
    if ($script:CommandLog.Count -gt 0) {
        $script:CommandLog | Export-Csv -LiteralPath $cmdCsv -NoTypeInformation -Encoding UTF8
    }
    $errFile = Join-Path $script:Paths.Errors ('errors_{0}.txt' -f $script:AcquisitionId)
    $allIssues = @($script:ErrorLog) + @($script:WarningLog)
    if ($allIssues.Count -gt 0) { $allIssues | Out-File -LiteralPath $errFile -Encoding UTF8 }
    else { 'Sin errores ni advertencias registrados.' | Out-File -LiteralPath $errFile -Encoding UTF8 }
    if ($script:MissingEvidence.Count -gt 0) {
        $script:MissingEvidence | Export-Csv -LiteralPath (Join-Path $script:Paths.Errors 'missing_evidence.csv') -NoTypeInformation -Encoding UTF8
    }
}

function Export-HashManifestAndVerify {
    



    if (-not $IncludeHashes) {
        Write-ForensicLog -Level WARN -Message 'IncludeHashes desactivado: sin manifiesto de integridad (no recomendado en pericial).'
        return
    }
    Write-ForensicLog -Message '--- Verificacion final de integridad de evidencias ---'
    Wait-HashPool   
    $mismatch = 0
    $toVerify = @($script:EvidenceList | Where-Object { $_.SHA256 -and $_.SHA256 -ne 'NOT_COMPUTED_SIZE_LIMIT' } | ForEach-Object { $_.EvidenceFile })
    Write-ForensicLog -Message ('Verificando {0} evidencias en paralelo ({1} hilos)...' -f $toVerify.Count, $script:HashWorkers)
    $nowHashes = Get-FileHashParallel -Paths $toVerify -Algorithm SHA256
    foreach ($ev in $script:EvidenceList) {
        if (-not $ev.SHA256 -or $ev.SHA256 -eq 'NOT_COMPUTED_SIZE_LIMIT') { $ev.VerifiedAtEnd = 'NOT_APPLICABLE'; continue }
        $now = $nowHashes[$ev.EvidenceFile]
        if ($now -eq $ev.SHA256) { $ev.VerifiedAtEnd = 'MATCH' }
        elseif ($script:VolatileEvidence -and ($script:VolatileEvidence -contains $ev.EvidenceFile)) {
            
            
            $ev.VerifiedAtEnd = ('VOLATIL: fichero en uso; hash inicial {0} / hash final {1}' -f $ev.SHA256, $now)
            Write-ForensicLog -Level WARN -Message ('VOLATIL (no es alteracion): {0} era un fichero en uso; su contenido cambio durante la adquisicion. Hash inicial y final registrados.' -f $ev.RelativePath)
        }
        elseif ($ev.RelativePath -match '^(03_Parsed_Evidence|05_Acquisition_Logs|07_Errors|00_Case_Metadata|06_Report|08_Timeline)[\\/]') {
            
            
            
            $ev.SHA256 = $now
            $ev.VerifiedAtEnd = 'RESELLADO (producto del script actualizado tras el primer hash)'
            Write-ForensicLog -Level INFO -Message ('RESELLADO (no es alteracion): {0} es un producto generado por el script y se actualizo tras su primer hash; se registra el hash final.' -f $ev.RelativePath)
        }
        else {
            $ev.VerifiedAtEnd = ('MISMATCH:{0}' -f $now)
            $mismatch++
            Write-ForensicLog -Level ERROR -Message ('INTEGRIDAD: hash divergente en {0}' -f $ev.RelativePath)
        }
    }
    Write-ForensicLog -Message ('Verificacion completada: {0} evidencias, {1} divergencias.' -f $script:EvidenceList.Count, $mismatch)

    $csv  = Join-Path $script:Paths.Hashes 'hash_manifest.csv'
    $json = Join-Path $script:Paths.Hashes 'hash_manifest.json'
    $script:EvidenceList | Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8
    try {
        [System.IO.File]::WriteAllText($json, ($script:EvidenceList | ConvertTo-Json -Depth 4), (New-Object System.Text.UTF8Encoding($false)))
    } catch { }
    
    $manifestHash = Get-EvidenceFileHash -Path $csv -Algorithm SHA256
    $seal = New-Object PSObject -Property @{
        AcquisitionId = $script:AcquisitionId
        ManifestFile = $csv; ManifestSHA256 = $manifestHash
        EvidenceCount = $script:EvidenceList.Count; MismatchCount = $mismatch
        SealedUTC = Get-NowUtcString
        Note = 'Para inmutabilidad plena: firmar este sello con clave del perito o sellado de tiempo cualificado (TSA).'
    }
    $seal | Export-Csv -LiteralPath (Join-Path $script:Paths.Hashes 'manifest_seal.csv') -NoTypeInformation -Encoding UTF8
    try {
        [System.IO.File]::WriteAllText((Join-Path $script:Paths.Hashes 'manifest_seal.json'), ($seal | ConvertTo-Json -Depth 3), (New-Object System.Text.UTF8Encoding($false)))
    } catch { }
}

function Export-UnifiedTimeline {
    




    if (-not $ExportParsedEvidence) { return }
    Write-ForensicLog -Message '--- Generando linea temporal unificada ---'
    $tlOut = Join-Path $script:Paths.Timeline 'unified_timeline.csv'
    $eventCsvs = @(Get-ChildItem -LiteralPath $script:Paths.ParsedCSV -Filter '*.csv' -ErrorAction SilentlyContinue |
                   Where-Object { $_.Name -match '^(2|3)\d[b]?_' })
    $all = New-Object System.Collections.ArrayList
    foreach ($f in $eventCsvs) {
        try {
            Import-Csv -LiteralPath $f.FullName | ForEach-Object { [void]$all.Add($_) }
        } catch { }
    }
    if ($all.Count -gt 0) {
        $all | Sort-Object -Property TimestampUTC | Export-Csv -LiteralPath $tlOut -NoTypeInformation -Encoding UTF8
        Register-Evidence -Path $tlOut -Category 'Timeline' -SourceDescription 'Union ordenada de eventos normalizados' -Notes ('{0} entradas' -f $all.Count)
    } else {
        Register-MissingEvidence -Evidence 'Timeline unificada' -Reason 'Sin CSV de eventos normalizados que unir'
    }
}

function ConvertTo-HtmlSafe {
    
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    return $Text.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;')
}

function Format-ReportCell {
    param($Value, [int]$Max = 0)
    if ($null -eq $Value) { return '' }
    $s = [string]$Value
    if ($Max -gt 0 -and $s.Length -gt $Max) { $s = $s.Substring(0, $Max) + [char]0x2026 }
    return (ConvertTo-HtmlSafe $s)
}

function Get-ReportCsv {
    



    param([string]$Base, [int]$MaxBytesForFull = 52428800)
    $path = Join-Path $script:Paths.ParsedCSV ($Base + '.csv')
    $res = New-Object PSObject -Property @{ Path=$path; Exists=$false; Rows=@(); Total=0; TooLarge=$false }
    if (-not (Test-Path -LiteralPath $path)) { return $res }
    $res.Exists = $true
    try {
        $len = (Get-Item -LiteralPath $path).Length
        if ($len -gt $MaxBytesForFull) {
            $res.TooLarge = $true
            try { $res.Total = [math]::Max(0, ([System.IO.File]::ReadAllLines($path)).Count - 1) } catch { }
            return $res
        }
        $rows = @(Import-Csv -LiteralPath $path)
        $res.Rows = $rows
        $res.Total = $rows.Count
    } catch { }
    return $res
}

function Select-ByEventId {
    param([array]$Rows, [int[]]$Ids)
    if (-not $Rows -or $Rows.Count -eq 0) { return @() }
    $set = @{}
    foreach ($i in $Ids) { $set[[string]$i] = $true }
    return @($Rows | Where-Object { $set.ContainsKey([string]$_.EventId) })
}

function New-ReportTable {
    
    param(
        [array]$Rows,
        [array]$Columns = $null,   
        [int]$MaxRows = 250,
        [string]$SourceCsv = $null,
        [int]$TotalCount = -1,
        [string]$EmptyText = 'Sin registros para este apartado en el periodo analizado.'
    )
    if (-not $Rows -or $Rows.Count -eq 0) { return ('<p class="empty">' + $EmptyText + '</p>') }
    if (-not $Columns) {
        $Columns = @()
        foreach ($p in $Rows[0].PSObject.Properties.Name) { $Columns += @{ P=$p; L=$p } }
    }
    $total = $(if ($TotalCount -ge 0) { $TotalCount } else { $Rows.Count })
    $show = $Rows
    $trunc = $false
    if ($Rows.Count -gt $MaxRows) { $show = $Rows[0..($MaxRows-1)]; $trunc = $true }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<div class="tablewrap"><table><thead><tr>')
    foreach ($c in $Columns) { [void]$sb.Append('<th>' + ([string]$c.L) + '</th>') }
    [void]$sb.Append('</tr></thead><tbody>')
    foreach ($r in $show) {
        [void]$sb.Append('<tr>')
        foreach ($c in $Columns) {
            $mx = 0; if ($c.ContainsKey('Max')) { $mx = [int]$c.Max }
            $val = Format-ReportCell $r.($c.P) $mx
            $cls = ''; if ($c.ContainsKey('Mono') -and $c.Mono) { $cls = ' class="mono"' }
            [void]$sb.Append('<td' + $cls + '>' + $val + '</td>')
        }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table></div>')
    if ($SourceCsv) {
        if ($trunc) {
            [void]$sb.Append('<p class="tnote">Se muestran ' + $MaxRows + ' de ' + $total + ' registros. Conjunto completo en <span class="mono">03_Parsed_Evidence\CSV\' + (ConvertTo-HtmlSafe $SourceCsv) + '</span>.</p>')
        } else {
            [void]$sb.Append('<p class="tnote">' + $total + ' registro(s). Fuente: <span class="mono">03_Parsed_Evidence\CSV\' + (ConvertTo-HtmlSafe $SourceCsv) + '</span>.</p>')
        }
    }
    return $sb.ToString()
}

function New-KeyValueTable {
    param($Row, [string[]]$Order = $null, [hashtable]$Labels = $null)
    if (-not $Row) { return '<p class="empty">No disponible.</p>' }
    $props = $(if ($Order) { $Order } else { @($Row.PSObject.Properties.Name) })
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<table class="kv"><tbody>')
    foreach ($p in $props) {
        $label = $p
        if ($Labels -and $Labels.ContainsKey($p)) { $label = $Labels[$p] }
        $v = Format-ReportCell $Row.$p
        [void]$sb.Append('<tr><th>' + $label + '</th><td>' + $v + '</td></tr>')
    }
    [void]$sb.Append('</tbody></table>')
    return $sb.ToString()
}

function New-CountSummaryTable {
    
    param([array]$Rows, [string]$Property, [string]$Label, [int]$Top = 15)
    if (-not $Rows -or $Rows.Count -eq 0) { return '' }
    $groups = $Rows | Group-Object -Property $Property | Sort-Object Count -Descending
    if (-not $groups -or $groups.Count -eq 0) { return '' }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<div class="tablewrap"><table class="mini"><thead><tr><th>' + $Label + '</th><th>Recuento</th></tr></thead><tbody>')
    $n = 0
    foreach ($g in $groups) {
        if ($n -ge $Top) { break }
        $name = $g.Name; if ($null -eq $name -or $name -eq '') { $name = '(sin valor)' }
        [void]$sb.Append('<tr><td>' + (ConvertTo-HtmlSafe ([string]$name)) + '</td><td class="num">' + $g.Count + '</td></tr>')
        $n++
    }
    [void]$sb.Append('</tbody></table></div>')
    return $sb.ToString()
}

function Export-HtmlSummary {
    




    Write-ForensicLog -Message '--- Generando informe pericial HTML ---'
    $H = New-Object System.Text.StringBuilder
    $add = { param($s) [void]$H.Append($s) }

    
    $sysCsv = Get-ReportCsv '01_system_identification'
    $sys = $(if ($sysCsv.Rows.Count -gt 0) { $sysCsv.Rows[0] } else { $null })
    $nowUtc = Get-NowUtcString
    $matchCount = @($script:EvidenceList | Where-Object { $_.VerifiedAtEnd -eq 'MATCH' }).Count
    $mismatchCount = @($script:EvidenceList | Where-Object { $_.VerifiedAtEnd -like 'MISMATCH*' }).Count

    
    & $add '<!DOCTYPE html><html lang="es"><head><meta charset="utf-8">'
    & $add '<meta name="viewport" content="width=device-width, initial-scale=1">'
    & $add ('<title>Informe pericial ' + (ConvertTo-HtmlSafe $script:CaseId) + '</title>')
    & $add @'
<style>
:root{--ink:#1b232d;--soft:#4c5763;--faint:#7b8592;--seal:#7a1f2b;--panel:#f5f3ee;--panel2:#eceae3;--line:#d9d5cc;--lineb:#b9b4a8;--a:#2f6b4f;--m:#9a6b1e;--b:#6b7280;--code:#f2f1ec;}
*{box-sizing:border-box;}
html{-webkit-print-color-adjust:exact;print-color-adjust:exact;}
body{margin:0;color:var(--ink);background:#e9e7e1;font-family:"Segoe UI",system-ui,Arial,sans-serif;font-size:13px;line-height:1.5;}
.sheet{max-width:1000px;margin:0 auto;background:#fff;padding:30px 40px 60px;box-shadow:0 2px 18px rgba(0,0,0,.12);}
h1,h2,h3,.serif{font-family:Cambria,Georgia,"Times New Roman",serif;}
.mono,code{font-family:Consolas,"Courier New",monospace;font-size:.86em;}
code{background:var(--code);border:1px solid var(--line);border-radius:3px;padding:0 .3em;}
.eyebrow{font-weight:700;font-size:10px;letter-spacing:.22em;text-transform:uppercase;color:var(--seal);margin:0 0 4px;}
h1{font-size:27px;line-height:1.12;margin:0 0 6px;font-weight:600;}
.sub{font-size:15px;color:var(--soft);font-style:italic;font-family:Cambria,Georgia,serif;margin:0 0 14px;}
h2{font-size:19px;margin:0 0 4px;font-weight:600;border-bottom:2px solid var(--ink);padding-bottom:5px;}
h2 .sn{color:var(--seal);font-family:"Segoe UI",sans-serif;font-size:12px;font-weight:700;letter-spacing:.06em;margin-right:8px;vertical-align:2px;}
h3{font-size:14px;margin:16px 0 4px;font-weight:600;}
section{margin-top:26px;}
p{margin:0 0 8px;}
.lead{color:var(--soft);font-size:13.5px;}
.muted{color:var(--soft);} .faint{color:var(--faint);font-size:12px;}
.topband{display:flex;justify-content:space-between;align-items:flex-start;border-top:3px solid var(--ink);padding-top:8px;}
.topband .brand{font-weight:700;font-size:11px;letter-spacing:.24em;text-transform:uppercase;}
.topband .refs{font-size:10.5px;color:var(--soft);text-align:right;line-height:1.5;}
.topband .refs b{color:var(--ink);}
.metagrid{display:grid;grid-template-columns:1fr 1fr;gap:6px 26px;margin:14px 0 4px;}
.metagrid .f{border-bottom:1px solid var(--line);padding-bottom:5px;}
.metagrid .k{font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:var(--faint);}
.metagrid .v{font-size:13.5px;} .metagrid .v.mono{font-size:11.5px;word-break:break-all;}
.kpis{display:flex;gap:10px;margin:16px 0 2px;flex-wrap:wrap;}
.kpi{flex:1;min-width:120px;border:1px solid var(--lineb);background:var(--panel);padding:10px 12px;}
.kpi .n{font-family:Cambria,Georgia,serif;font-size:23px;font-weight:700;line-height:1;}
.kpi .l{font-size:10.5px;letter-spacing:.06em;text-transform:uppercase;color:var(--soft);margin-top:4px;}
.kpi.ok .n{color:var(--a);} .kpi.warn .n{color:var(--m);} .kpi.bad .n{color:var(--seal);}
.notice{background:var(--panel);border:1px solid var(--lineb);border-left:3px solid var(--seal);padding:12px 14px;margin:10px 0;}
.notice h3{margin-top:0;color:var(--seal);}
.notice p{font-size:12.5px;color:var(--soft);margin-bottom:5px;} .notice p:last-child{margin-bottom:0;}
.callout{border:1px solid var(--lineb);border-left:3px solid var(--ink);background:#fbfaf7;padding:11px 14px;margin:10px 0;}
.callout p{margin:0;font-size:12.5px;color:var(--soft);}
.toc{border:1px solid var(--line);}
.toc a{display:flex;justify-content:space-between;text-decoration:none;color:var(--ink);padding:7px 12px;border-bottom:1px solid var(--line);font-size:13px;}
.toc a:last-child{border-bottom:0;} .toc a:hover{background:var(--panel);}
.toc a .n{color:var(--seal);font-weight:700;width:28px;}
.toc a .t{flex:1;}
.tablewrap{overflow-x:auto;margin:8px 0;}
table{width:100%;border-collapse:collapse;font-size:11.5px;}
thead{display:table-header-group;}
th{background:var(--ink);color:#fff;text-align:left;font-weight:600;font-size:10.5px;letter-spacing:.02em;padding:6px 8px;vertical-align:top;}
td{border-bottom:1px solid var(--line);padding:5px 8px;vertical-align:top;line-height:1.35;}
tbody tr:nth-child(even){background:#faf9f6;} tbody tr{break-inside:avoid;}
td.mono{font-family:Consolas,monospace;font-size:10.5px;} td.num{text-align:right;font-variant-numeric:tabular-nums;}
table.kv th{width:34%;background:var(--panel);color:var(--ink);border-bottom:1px solid var(--line);font-weight:600;}
table.kv td{font-size:12px;}
table.mini{width:auto;min-width:280px;} table.mini th{font-size:10px;}
.summaryrow{display:flex;gap:20px;flex-wrap:wrap;} .summaryrow>div{flex:1;min-width:250px;}
.tnote{font-size:11px;color:var(--faint);margin:4px 0 0;}
.empty{font-size:12.5px;color:var(--faint);font-style:italic;background:var(--panel);border:1px dashed var(--lineb);padding:8px 12px;}
.chip{display:inline-block;font-size:10px;font-weight:700;letter-spacing:.05em;padding:1px 6px;border-radius:2px;text-transform:uppercase;}
.chip.a{background:#e6efe9;color:var(--a);border:1px solid #bcd6c6;}
.chip.m{background:#f3ebda;color:var(--m);border:1px solid #e0cfa6;}
.chip.b{background:#eceef1;color:var(--b);border:1px solid #cfd4da;}
.dot{width:9px;height:9px;border-radius:50%;display:inline-block;margin-right:6px;}
.certgrid{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:8px;}
.cert{border:1px solid var(--lineb);padding:9px 11px;} .cert .ct{font-weight:700;font-size:12.5px;} .cert .cd{font-size:12px;color:var(--soft);}
.footer{margin-top:34px;border-top:1px solid var(--line);padding-top:10px;font-size:11px;color:var(--faint);}
@media print{
  body{background:#fff;} .sheet{box-shadow:none;max-width:none;padding:0;}
  a{color:var(--ink);text-decoration:none;} .toc{page-break-inside:avoid;}
  section{page-break-inside:auto;} h2{page-break-after:avoid;}
  @page{size:A4;margin:16mm 14mm;}
}
</style></head><body><div class="sheet">
'@

    
    & $add '<div class="topband"><div class="brand">Peritaje inform&#225;tico forense</div>'
    & $add '<div class="refs">Conforme a <b>UNE&nbsp;71505</b> &#183; <b>UNE&nbsp;71506</b><br>Informe pericial <b>UNE&nbsp;197001</b> &#183; <b>UNE&nbsp;197010</b><br>Adquisici&#243;n en vivo &#183; impacto m&#237;nimo</div></div>'
    & $add '<div class="eyebrow">Informe de adquisici&#243;n y hallazgos</div>'
    & $add '<h1>Informe pericial inform&#225;tico</h1>'
    & $add '<div class="sub">Investigaci&#243;n de acceso no autorizado, movimiento lateral, borrado y exfiltraci&#243;n de datos en sistema Windows.</div>'

    & $add '<div class="metagrid">'
    $mf = {
        param($k,$v,$mono)
        $cls = $(if ($mono) { 'v mono' } else { 'v' })
        '<div class="f"><div class="k">' + $k + '</div><div class="' + $cls + '">' + (ConvertTo-HtmlSafe ([string]$v)) + '</div></div>'
    }
    & $add (& $mf 'N&#186; de expediente' $script:CaseId $false)
    & $add (& $mf 'Organizaci&#243;n' $Organization $false)
    & $add (& $mf 'Perito / investigador' $Examiner $false)
    & $add (& $mf 'Identificador de adquisici&#243;n' $script:AcquisitionId $true)
    & $add (& $mf 'Equipo analizado' $(if ($sys) { $sys.ComputerName } else { $env:COMPUTERNAME }) $false)
    & $add (& $mf 'Sistema operativo' $(if ($sys) { ('{0} (build {1}, {2})' -f $sys.OSCaption, $sys.OSBuild, $sys.OSArchitecture) } else { '-' }) $false)
    $perLabel = $(if ($IncidentStart -ne [datetime]::MinValue) { 'Ventana de adquisicion (local)' } else { 'Ventana de adquisicion (local; sin periodo de incidente definido: historico completo)' })
    & $add (& $mf $perLabel ('{0} a {1}' -f $StartDate, $EndDate) $false)
    if ($IncidentStart -ne [datetime]::MinValue) { & $add (& $mf 'Periodo del incidente (local)' ('{0} a {1}' -f $IncidentStart, $(if ($IncidentEnd -ne [datetime]::MinValue) { $IncidentEnd } else { $EndDate })) $false) }
    if ($ExaminerSince -ne [datetime]::MinValue) { & $add (& $mf 'Inicio de la intervencion pericial' ('{0}' -f $ExaminerSince) $false) }
    & $add (& $mf 'Zona horaria del sistema' $(if ($sys) { ('{0} (UTC {1} min)' -f $sys.TimeZoneId, $sys.UTCOffsetMinutes) } else { '-' }) $false)
    & $add (& $mf 'Ejecuci&#243;n con privilegios admin.' $script:IsAdmin $false)
    & $add (& $mf 'Inicio / fin (UTC)' ('{0} a {1}' -f $script:StartUtc.ToString($script:TsFmt), $nowUtc) $true)
    & $add (& $mf 'Huella SHA-256 del script' $script:SelfHash $true)
    & $add (& $mf 'PowerShell' $(if ($sys) { $sys.PSVersion } else { $PSVersionTable.PSVersion.ToString() }) $false)
    & $add '</div>'

    
    & $add '<div class="kpis">'
    & $add ('<div class="kpi"><div class="n">' + $script:EvidenceList.Count + '</div><div class="l">Evidencias adquiridas</div></div>')
    & $add ('<div class="kpi ok"><div class="n">' + $matchCount + '</div><div class="l">Integridad verificada (MATCH)</div></div>')
    & $add ('<div class="kpi ' + $(if ($mismatchCount -gt 0) { 'bad' } else { '' }) + '"><div class="n">' + $mismatchCount + '</div><div class="l">Divergencias de hash</div></div>')
    $benignK = @('NOT_INSTALLED','NOT_APPLICABLE','EMPTY','DISABLED','NOT_FOUND','REQUIRES_OFFLINE_ACQUISITION','REQUIRES_EXTERNAL_SOURCE')
    $realFails = @($script:MissingEvidence | Where-Object { -not ($benignK -contains $_.Status) }).Count
    $legit = $script:MissingEvidence.Count - $realFails
    & $add ('<div class="kpi"><div class="n">' + $legit + '</div><div class="l">Artefactos ausentes (legitimos)</div></div>')
    & $add ('<div class="kpi ' + $(if ($realFails -gt 0) { 'warn' } else { '' }) + '"><div class="n">' + $realFails + '</div><div class="l">Fallos reales de adquisicion</div></div>')
    & $add '</div>'

    
    & $add '<div class="notice"><h3>Naturaleza y l&#237;mites de este informe</h3>'
    & $add '<p>Este documento presenta la informaci&#243;n adquirida del sistema y los hallazgos derivados. La adquisici&#243;n en vivo altera inevitablemente el sistema; ese impacto se documenta en <span class="mono">00_Case_Metadata\Impact_Statement.txt</span>. Numerosos registros solo existen si la auditor&#237;a estaba habilitada antes del incidente: su ausencia no prueba que un hecho no ocurriera.</p>'
    & $add '<p>Toda conclusi&#243;n distingue entre <b>hecho acreditado, inferencia, indicador, hip&#243;tesis</b> e <b>informaci&#243;n no disponible</b>. La presencia de una herramienta no acredita su uso; el acceso a un archivo no acredita su copia o exfiltraci&#243;n. La correlaci&#243;n y la validaci&#243;n pericial se realizan conforme a UNE&nbsp;71506.</p></div>'

    & $add '<div class="certgrid">'
    & $add '<div class="cert"><div class="ct"><span class="dot" style="background:#2f6b4f"></span>Hecho acreditado</div><div class="cd">Evidencia &#237;ntegra y no ambigua.</div></div>'
    & $add '<div class="cert"><div class="ct"><span class="dot" style="background:#3a6ea5"></span>Inferencia</div><div class="cd">Correlaci&#243;n razonada de varias evidencias.</div></div>'
    & $add '<div class="cert"><div class="ct"><span class="dot" style="background:#9a6b1e"></span>Indicador</div><div class="cd">Compatible con la hip&#243;tesis y con explicaciones leg&#237;timas.</div></div>'
    & $add '<div class="cert"><div class="ct"><span class="dot" style="background:#7a1f2b"></span>Hip&#243;tesis</div><div class="cd">No confirmada; requiere m&#225;s evidencia.</div></div>'
    & $add '</div>'

    
    $toc = @(
        @('A','Identificaci&#243;n del sistema y cobertura de registros'),
        @('B','Cuentas de usuario y grupos privilegiados'),
        @('C','Inicios de sesi&#243;n y autenticaciones'),
        @('Q','Actividad de usuario (atribuci&#243;n)'),
        @('R','Dispositivos USB conectados'),
        @('S','Navegaci&#243;n web e IA por navegador'),
        @('T','Inicios de sesi&#243;n en el periodo analizado y correlaci&#243;n'),
        @('U','Eventos hist&#243;ricos recuperados (VSS / archivados)'),
        @('Z','Anexo general de c&#243;digos de evento'),
        @('D','Gesti&#243;n de cuentas y grupos'),
        @('P','Actividad de contrase&#241;as, cuentas y grupos'),
        @('E','Ejecuci&#243;n de procesos y comandos'),
        @('F','Accesos remotos y movimiento lateral'),
        @('G','Persistencia (tareas, servicios, WMI)'),
        @('H','Red y conexiones'),
        @('I','Artefactos de archivos y borrado'),
        @('O','Archivos eliminados (trazabilidad forense)'),
        @('J','Antiforensia y estado de la defensa'),
        @('K','Herramientas de inteligencia artificial'),
        @('L','Integridad de la evidencia'),
        @('M','Cadena de custodia (comandos ejecutados)'),
        @('N','Evidencias no disponibles')
    )
    & $add '<section><h2>&#205;ndice</h2><div class="toc">'
    foreach ($t in $toc) { & $add ('<a href="#sec' + $t[0] + '"><span class="n">' + $t[0] + '</span><span class="t">' + $t[1] + '</span></a>') }
    & $add '</div></section>'

    
    $secCsv = Get-ReportCsv '20_security_events'
    $secRows = $secCsv.Rows
    $secBig = $secCsv.TooLarge
    $secBigNote = ''
    if ($secBig) { $secBigNote = '<p class="empty">El registro de seguridad normalizado es muy voluminoso (' + $secCsv.Total + ' registros) y no se detalla en el informe para preservar recursos. Cons&#250;ltese <span class="mono">03_Parsed_Evidence\CSV\20_security_events.csv</span> y la l&#237;nea temporal unificada (05).</p>' }

    $colEvtBase = @(
        @{P='TimestampUTC';L='Fecha UTC';Mono=$true},
        @{P='EventId';L='ID';Mono=$true},
        @{P='User';L='Usuario'},
        @{P='UserSID';L='SID';Mono=$true;Max=24},
        @{P='Notes';L='Detalle';Max=90}
    )

    
    & $add '<section id="secA"><h2><span class="sn">&#167;A</span>Identificaci&#243;n del sistema y cobertura de registros</h2>'
    & $add '<p class="lead">Identidad del equipo, fiabilidad del reloj y alcance temporal real de los registros disponibles.</p>'
    if ($sys) {
        $ord = @('ComputerName','Domain','PartOfDomain','Manufacturer','Model','BIOSSerialNumber','OSCaption','OSVersion','OSBuild','OSArchitecture','OSInstallDateLocal','LastBootLocal','LastBootUTC','TimeZoneId','UTCOffsetMinutes','SystemLocale','PSVersion')
        $lbl = @{ComputerName='Nombre de equipo';Domain='Dominio';PartOfDomain='Unido a dominio';Manufacturer='Fabricante';Model='Modelo';BIOSSerialNumber='N&#186; de serie (BIOS)';OSCaption='Sistema operativo';OSVersion='Versi&#243;n';OSBuild='Compilaci&#243;n';OSArchitecture='Arquitectura';OSInstallDateLocal='Instalaci&#243;n (local)';LastBootLocal='&#218;ltimo arranque (local)';LastBootUTC='&#218;ltimo arranque (UTC)';TimeZoneId='Zona horaria';UTCOffsetMinutes='Desfase UTC (min)';SystemLocale='Configuraci&#243;n regional';PSVersion='PowerShell'}
        & $add (New-KeyValueTable -Row $sys -Order $ord -Labels $lbl)
    } else { & $add '<p class="empty">No se recuper&#243; la identificaci&#243;n del sistema.</p>' }
    $inv = Get-ReportCsv '02_eventlog_inventory'
    
    $tsync = Get-ReportCsv '01b_time_sync_status'
    if ($tsync.Rows.Count -gt 0) {
        $t0 = $tsync.Rows[0]
        & $add '<h3>Sincronizaci&#243;n horaria del equipo</h3>'
        $running = ([string]$t0.W32TimeServiceStatus -eq 'Running')
        $cls = $(if ($running) { 'callout' } else { 'notice' })
        & $add ('<div class="' + $cls + '"><p><b>Servicio Hora de Windows (W32Time):</b> ' + (ConvertTo-HtmlSafe ([string]$t0.W32TimeServiceStatus)) + ' (inicio: ' + (ConvertTo-HtmlSafe ([string]$t0.W32TimeStartMode)) + '). <b>Servidor NTP configurado:</b> ' + $(if ($t0.NtpServer) { ConvertTo-HtmlSafe ([string]$t0.NtpServer) } else { 'no configurado' }) + '. ' + (ConvertTo-HtmlSafe ([string]$t0.Assessment)) + '</p></div>')
    }
    & $add '<h3>Cobertura de los registros de eventos</h3>'
    & $add '<p class="muted">El evento m&#225;s antiguo y m&#225;s reciente por canal revela si el periodo investigado est&#225; cubierto o si el registro pudo rotar (sobrescritura). La columna <b>Estado</b> distingue un canal operativo de uno vac&#237;o, deshabilitado o inaccesible.</p>'
    $colInv = @(
        @{P='Estado';L='Estado';Mono=$true;Max=14},
        @{P='RecordCount';L='Eventos';Mono=$true},
        @{P='OldestEventUTC';L='Mas antiguo (UTC)';Mono=$true},
        @{P='OldestEventLocal';L='Mas antiguo (local)';Mono=$true},
        @{P='NewestEventUTC';L='Mas reciente (UTC)';Mono=$true},
        @{P='LogName';L='Canal';Max=52},
        @{P='LogFilePath';L='Ruta';Max=48}
    )
    & $add (New-ReportTable -Rows $inv.Rows -Columns $colInv -MaxRows 80 -SourceCsv '02_eventlog_inventory.csv')
    & $add '</section>'

    
    & $add '<section id="secB"><h2><span class="sn">&#167;B</span>Cuentas de usuario y grupos privilegiados</h2>'
    & $add '<h3>Cuentas locales</h3>'
    & $add (New-ReportTable -Rows (Get-ReportCsv '10_local_users').Rows -MaxRows 100 -SourceCsv '10_local_users.csv')
    & $add '<h3>Miembros de grupos privilegiados</h3>'
    & $add (New-ReportTable -Rows (Get-ReportCsv '11_privileged_group_members').Rows -MaxRows 100 -SourceCsv '11_privileged_group_members.csv')
    & $add '<h3>Perfiles de usuario</h3>'
    & $add (New-ReportTable -Rows (Get-ReportCsv '12_user_profiles').Rows -MaxRows 100 -SourceCsv '12_user_profiles.csv')
    & $add '</section>'

    
    
    $gtl = Get-ReportCsv '00_global_timeline'
    if ($gtl.Rows.Count -gt 0) {
        & $add '<section id="secTL"><h2><span class="sn">&#167;B2</span>Timeline forense global</h2>'
        & $add '<p class="lead">Vista cronol&#243;gica unificada de todos los hechos <b>datados</b> del caso: inicios de sesi&#243;n, procesos, contrase&#241;as, RDP, navegaci&#243;n, descargas, ejecuci&#243;n de programas, servicios, USB, borrados, VSS y Defender. Cada fila conserva su <b>fuente</b> y <b>nivel de confianza</b>. Es el hilo temporal de referencia para seguir la secuencia de los hechos.</p>'
        & $add '<p class="muted">Ordenada de m&#225;s antigua a m&#225;s reciente. Solo incluye eventos con fecha fiable; los artefactos sin fecha propia se detallan en sus secciones respectivas. La reconstrucci&#243;n exhaustiva al segundo (supertimeline de disco) se realiza en fr&#237;o con plaso sobre la evidencia preservada.</p>'
        $colTL = @(
            @{P='TimestampUTC';L='Fecha UTC';Mono=$true},
            @{P='TimestampLocal';L='Hora local';Mono=$true},
            @{P='Category';L='Categoria';Max=14},
            @{P='Action';L='Accion';Max=40},
            @{P='User';L='Usuario';Max=22},
            @{P='SourceIP';L='IP origen';Mono=$true},
            @{P='Object';L='Objeto';Mono=$true;Max=44},
            @{P='EvidenceSource';L='Fuente';Max=24},
            @{P='Confidence';L='Conf.';Max=8},
            @{P='Nota';L='Nota';Max=26}
        )
        & $add '<p class="muted">Las filas marcadas como <b>ACTIVIDAD DEL EXAMINADOR</b> son posteriores al inicio de la intervenci&#243;n pericial (par&#225;metro <span class="mono">-ExaminerSince</span> o inicio de esta ejecuci&#243;n) y no deben atribuirse al investigado.</p>'
        
        
        $tlRows = @($gtl.Rows)
        $tlPeriod = @(); $tlRest = @()
        if ($script:IncidentStartUtc -and $script:IncidentEndUtc) {
            foreach ($row in $tlRows) {
                $inP = $false
                try { $dtT = [datetime]::Parse([string]$row.TimestampUTC).ToUniversalTime(); $inP = ($dtT -ge $script:IncidentStartUtc -and $dtT -le $script:IncidentEndUtc) } catch { }
                if ($inP) { $tlPeriod += $row } else { $tlRest += $row }
            }
            $tlPeriod = @($tlPeriod | Sort-Object TimestampUTC -Descending)
            $tlRest = @($tlRest | Sort-Object TimestampUTC -Descending)
            & $add ('<h3>Hechos dentro del periodo analizado (' + $tlPeriod.Count + ')</h3>')
            & $add (New-ReportTable -Rows $tlPeriod -Columns $colTL -MaxRows 800 -SourceCsv '00_global_timeline.csv' -EmptyText 'Sin eventos datados dentro del periodo analizado.')
            & $add ('<h3>Resto de hechos datados (' + $tlRest.Count + '; de mas reciente a mas antiguo)</h3>')
            & $add (New-ReportTable -Rows $tlRest -Columns $colTL -MaxRows 500 -SourceCsv '00_global_timeline.csv' -EmptyText 'Sin mas eventos datados.')
        } else {
            $tlRows = @($tlRows | Sort-Object TimestampUTC -Descending)
            & $add (New-ReportTable -Rows $tlRows -Columns $colTL -MaxRows 1000 -SourceCsv '00_global_timeline.csv' -EmptyText 'Sin eventos datados para la timeline.')
        }
        & $add '</section>'
    }

    & $add '<section id="secC"><h2><span class="sn">&#167;C</span>Inicios de sesi&#243;n y autenticaciones</h2>'
    if ($secBig) { & $add $secBigNote }
    elseif (-not $secRows -or $secRows.Count -eq 0) { & $add '<p class="empty">Sin eventos de seguridad normalizados en el periodo. Comprobar con <span class="mono">auditpol /get /category:*</span> que la auditoria de inicio de sesion esta activa, y que el registro Security no ha rotado por debajo del periodo (ver cobertura en el apartado A).</p>' }
    else {
        $logons  = Select-ByEventId -Rows $secRows -Ids @(4624)
        $fails   = Select-ByEventId -Rows $secRows -Ids @(4625)
        $explicit= Select-ByEventId -Rows $secRows -Ids @(4648)
        & $add ('<p class="lead">Inicios correctos: <b>' + $logons.Count + '</b> &#183; fallidos: <b>' + $fails.Count + '</b> &#183; con credenciales expl&#237;citas (RunAs): <b>' + $explicit.Count + '</b>.</p>')
        $allLogon = @($logons + $fails)
        if ($allLogon.Count -gt 0) {
            $stamps = @($allLogon | ForEach-Object { $_.TimestampUTC } | Where-Object { $_ } | Sort-Object)
            if ($stamps.Count -gt 0) {
                & $add ('<p class="muted">Cobertura real de estos eventos en el registro: desde <span class="mono">' + (ConvertTo-HtmlSafe ([string]$stamps[0])) + '</span> hasta <span class="mono">' + (ConvertTo-HtmlSafe ([string]$stamps[-1])) + '</span> (UTC). Antes de esa fecha el registro Security pudo rotar; los hechos anteriores se buscan en otras fuentes o en instant&#225;neas/imagen offline.</p>')
            }
        }
        & $add '<div class="summaryrow">'
        & $add ('<div><h3>Por tipo de inicio</h3>' + (New-CountSummaryTable -Rows $logons -Property 'LogonType' -Label 'Tipo (logon type)') + '</div>')
        & $add ('<div><h3>Por usuario</h3>' + (New-CountSummaryTable -Rows $logons -Property 'User' -Label 'Usuario') + '</div>')
        & $add ('<div><h3>Por IP de origen</h3>' + (New-CountSummaryTable -Rows $logons -Property 'SourceIP' -Label 'IP de origen') + '</div>')
        & $add '</div>'
        $colLogon = @(
            @{P='TimestampUTC';L='Fecha UTC';Mono=$true},@{P='TimestampLocal';L='Hora local';Mono=$true},@{P='EventId';L='ID';Mono=$true},
            @{P='User';L='Usuario'},@{P='LogonType';L='Tipo'},@{P='SourceIP';L='IP origen';Mono=$true},
            @{P='WorkstationName';L='Estaci&#243;n'},@{P='LogonProcessName';L='Proc. inicio';Max=20},@{P='ProcessName';L='Proceso';Max=42}
        )
        & $add '<h3>Inicios remotos y por red (tipos 3, 10)</h3>'
        & $add '<p class="muted">El tipo indica la v&#237;a: <b>3</b> = red (acceso a recurso compartido, autenticaci&#243;n remota); <b>10</b> = escritorio remoto (RDP). La IP de origen puede no constar en inicios locales o de servicio por su naturaleza.</p>'
        $remoteLogons = @($logons | Where-Object { $_.LogonType -eq '10' -or $_.LogonType -eq '3' })
        & $add (New-ReportTable -Rows $remoteLogons -Columns $colLogon -MaxRows 200 -SourceCsv '20_security_events.csv' -EmptyText 'Sin inicios de sesi&#243;n remotos/por red en el periodo.')
        & $add '<h3>Intentos fallidos de inicio de sesion</h3>'
        if ($fails.Count -gt 0) { & $add ('<div><h4>Usuarios objetivo de intentos fallidos (recuento)</h4>' + (New-CountSummaryTable -Rows $fails -Property 'User' -Label 'Usuario') + '</div>') }
        $colFail = @(
            @{P='TimestampUTC';L='Fecha UTC';Mono=$true},@{P='TimestampLocal';L='Hora local';Mono=$true},
            @{P='User';L='Usuario'},@{P='LogonType';L='Tipo'},@{P='SourceIP';L='IP origen';Mono=$true},
            @{P='WorkstationName';L='Estaci&#243;n'},@{P='FailureReason';L='Motivo del fallo';Max=44},@{P='ProcessName';L='Proceso';Max=30}
        )
        & $add '<p class="muted">La columna <b>Motivo del fallo</b> traduce el c&#243;digo Status/SubStatus del evento (p.ej. contrase&#241;a incorrecta, cuenta inexistente, cuenta bloqueada), conservando el c&#243;digo hexadecimal original. Es clave para distinguir un error puntual de un patr&#243;n de fuerza bruta.</p>'
        & $add (New-ReportTable -Rows $fails -Columns $colFail -MaxRows 200 -SourceCsv '20_security_events.csv' -EmptyText 'Sin intentos fallidos registrados.')
        & $add '<h3>Uso de credenciales expl&#237;citas (4648)</h3>'
        & $add (New-ReportTable -Rows $explicit -Columns $colEvtBase -MaxRows 150 -SourceCsv '20_security_events.csv' -EmptyText 'Sin uso de credenciales expl&#237;citas registrado.')
    }
    & $add '</section>'

    
    & $add '<section id="secQ"><h2><span class="sn">&#167;Q</span>Actividad de usuario (atribuci&#243;n)</h2>'
    & $add '<p class="lead">Artefactos por usuario (ligados a su SID) que acreditan qu&#233; hizo <b>esa cuenta</b>: programas que ejecut&#243;, archivos que abri&#243;, carpetas que visit&#243; (aunque ya no existan), y rutas/comandos/b&#250;squedas que tecle&#243;. Es la base para atribuir acciones a una <b>cuenta de usuario determinada</b>; la vinculaci&#243;n de esa cuenta con una persona f&#237;sica es una valoraci&#243;n que debe apoyarse en indicios adicionales.</p>'
    & $add '<h3>Programas ejecutados por el usuario (UserAssist)</h3>'
    & $add '<p class="muted">Registra ejecuciones de programas de interfaz por cuenta, con n&#250;mero de veces y &#250;ltima ejecuci&#243;n.</p>'
    $colUA = @(
        @{P='User';L='Usuario'},
        @{P='Program';L='Programa';Mono=$true;Max=70},
        @{P='RunCount';L='Veces';Mono=$true},
        @{P='LastRunUTC';L='Ultima ejecucion (UTC)';Mono=$true}
    )
    & $add (New-ReportTable -Rows (Get-ReportCsv '30_userassist').Rows -Columns $colUA -MaxRows 300 -SourceCsv '30_userassist.csv' -EmptyText 'Sin datos de UserAssist (ninguna hive de usuario cargada o sin entradas).')
    & $add '<h3>Archivos abiertos (RecentDocs)</h3>'
    & $add '<div class="callout"><p><b>Sobre la datacion:</b> RecentDocs y los MRU del Registro <b>no guardan una fecha por cada entrada</b>. La &#250;nica marca temporal fiable es el <span class="mono">LastWrite</span> de la clave, que corresponde a la <b>entrada mas reciente</b> (posici&#243;n 0 del orden MRU). Por eso solo esa fila lleva fecha, con confianza <b>Aproximada</b>; el resto se muestra <b>sin fecha</b> (no se inventa). La datacion exacta por entrada requiere correlaci&#243;n con Jump Lists, .lnk o el sistema de archivos, o analisis offline.</p></div>'
    $colRD = @(@{P='TimestampUTC';L='Fecha (aprox.)';Mono=$true},@{P='TimestampConfidence';L='Confianza';Max=12},@{P='User';L='Usuario'},@{P='Extension';L='Tipo'},@{P='FileName';L='Archivo';Mono=$true;Max=66})
    & $add (New-ReportTable -Rows (Get-ReportCsv '31_recent_docs').Rows -Columns $colRD -MaxRows 300 -SourceCsv '31_recent_docs.csv' -EmptyText 'Sin archivos recientes registrados.')
    & $add '<h3>Comandos y rutas tecleados (RunMRU / TypedPaths)</h3>'
    & $add (New-ReportTable -Rows (Get-ReportCsv '32_run_mru').Rows -Columns @(@{P='TimestampUTC';L='Fecha (aprox.)';Mono=$true},@{P='TimestampConfidence';L='Confianza';Max=12},@{P='User';L='Usuario'},@{P='Command';L='Comando (Win+R)';Mono=$true;Max=64}) -MaxRows 150 -SourceCsv '32_run_mru.csv' -EmptyText 'Sin comandos en el dialogo Ejecutar.')
    & $add (New-ReportTable -Rows (Get-ReportCsv '33_typed_paths').Rows -Columns @(@{P='User';L='Usuario'},@{P='Path';L='Ruta escrita en el Explorador';Mono=$true;Max=80}) -MaxRows 150 -SourceCsv '33_typed_paths.csv' -EmptyText 'Sin rutas tecleadas en el Explorador.')
    & $add '<h3>B&#250;squedas del Explorador y URLs (WordWheelQuery / TypedURLs)</h3>'
    & $add (New-ReportTable -Rows (Get-ReportCsv '34_explorer_searches').Rows -Columns @(@{P='TimestampUTC';L='Fecha (aprox.)';Mono=$true},@{P='TimestampConfidence';L='Confianza';Max=12},@{P='User';L='Usuario'},@{P='SearchTerm';L='Termino buscado';Max=48}) -MaxRows 150 -SourceCsv '34_explorer_searches.csv' -EmptyText 'Sin busquedas del Explorador registradas.')
    & $add (New-ReportTable -Rows (Get-ReportCsv '35_typed_urls').Rows -Columns @(@{P='User';L='Usuario'},@{P='Url';L='URL escrita';Mono=$true;Max=70}) -MaxRows 150 -SourceCsv '35_typed_urls.csv' -EmptyText 'Sin URLs escritas.')
    & $add '<h3>Carpetas visitadas (ShellBags, extracci&#243;n best-effort)</h3>'
    & $add (New-ReportTable -Rows (Get-ReportCsv '36_shellbags').Rows -Columns @(@{P='User';L='Usuario'},@{P='FolderOrItem';L='Carpeta/elemento';Max=60},@{P='Hive';L='Origen'}) -MaxRows 300 -SourceCsv '36_shellbags.csv' -EmptyText 'Sin ShellBags extraidos.')
    & $add '<div class="callout"><p>UserAssist aporta <b>fecha</b> de &#250;ltima ejecuci&#243;n; RecentDocs, RunMRU, TypedPaths, b&#250;squedas y ShellBags acreditan la acci&#243;n pero <b>no llevan fecha por entrada</b> (no se inventan marcas de tiempo). La extracci&#243;n de ShellBags es best-effort (nombres de carpeta); el an&#225;lisis estructurado completo y los perfiles de usuarios <b>sin sesi&#243;n</b> se realizan offline sobre NTUSER.DAT/UsrClass.dat.</p></div>'
    & $add '</section>'

    
    & $add '<section id="secR"><h2><span class="sn">&#167;R</span>Dispositivos USB conectados</h2>'
    & $add '<p class="lead">Unidades de almacenamiento USB que se han conectado al equipo, con su <b>nombre, n&#250;mero de serie</b> y las fechas de <b>primera conexi&#243;n, &#250;ltima conexi&#243;n y &#250;ltima extracci&#243;n</b>. Relevante para exfiltraci&#243;n de datos a medios extra&#237;bles.</p>'
    $colUsb = @(
        @{P='FriendlyName';L='Dispositivo';Max=40},
        @{P='Serial';L='Numero de serie';Mono=$true;Max=30},
        @{P='FirstConnectUTC';L='Primera conexion (UTC)';Mono=$true},
        @{P='LastConnectUTC';L='Ultima conexion (UTC)';Mono=$true},
        @{P='LastRemovedUTC';L='Ultima extraccion (UTC)';Mono=$true}
    )
    & $add (New-ReportTable -Rows (Get-ReportCsv '44_usb_devices').Rows -Columns $colUsb -MaxRows 200 -SourceCsv '44_usb_devices.csv' -EmptyText 'No se registraron dispositivos de almacenamiento USB (o sin privilegios para leer USBSTOR).')
    & $add '<div class="callout"><p>Las fechas provienen de las propiedades del dispositivo en el registro (identificadores 0064/0066/0067). El log <span class="mono">setupapi.dev.log</span> (preservado) conserva la primera instalaci&#243;n fechada de cada dispositivo.</p></div>'
    & $add '</section>'

    
    & $add '<section id="secS"><h2><span class="sn">&#167;S</span>Navegaci&#243;n web e IA por navegador</h2>'
    & $add '<p class="lead">URLs extra&#237;das del historial de los navegadores, con &#233;nfasis en el <b>uso de herramientas de IA por web</b> (ChatGPT, Claude, Gemini, Copilot&#8230;) y en servicios de <b>nube/transferencia</b> (posible exfiltraci&#243;n).</p>'
    
    $htl = Get-ReportCsv '47_browser_history_timeline'
    if ($htl.Rows.Count -gt 0) {
        & $add '<h3>Historial cronol&#243;gico de navegaci&#243;n (con fecha por visita)</h3>'
        & $add '<p class="muted">Visitas ordenadas por fecha, parseadas directamente del historial SQLite del navegador (tablas <span class="mono">visits/urls</span> en Chromium, <span class="mono">moz_historyvisits</span> en Firefox). La fecha por visita es <b>directa</b> (confianza Alta).</p>'
        $colHtl = @(
            @{P='TimestampUTC';L='Fecha UTC';Mono=$true},
            @{P='TimestampLocal';L='Hora local';Mono=$true},
            @{P='User';L='Usuario'},
            @{P='Browser';L='Navegador'},
            @{P='Category';L='Cat.';Max=8},
            @{P='Url';L='URL';Mono=$true;Max=60},
            @{P='VisitCount';L='Visitas';Mono=$true}
        )
        & $add (New-ReportTable -Rows $htl.Rows -Columns $colHtl -MaxRows 500 -SourceCsv '47_browser_history_timeline.csv' -EmptyText 'Sin historial con fecha.')
    }
    $dtl = Get-ReportCsv '48_browser_downloads'
    if ($dtl.Rows.Count -gt 0) {
        & $add '<h3>Descargas (con fecha)</h3>'
        $colDl = @(
            @{P='StartTimeUTC';L='Inicio (UTC)';Mono=$true},
            @{P='User';L='Usuario'},
            @{P='DownloadPath';L='Archivo descargado';Mono=$true;Max=52},
            @{P='SourceUrl';L='URL de origen';Mono=$true;Max=52}
        )
        & $add (New-ReportTable -Rows $dtl.Rows -Columns $colDl -MaxRows 200 -SourceCsv '48_browser_downloads.csv' -EmptyText 'Sin descargas registradas.')
    }
    & $add '<h3>Uso de servicios de IA por navegador</h3>'
    $colAiWeb = @(
        @{P='TimestampUTC';L='Fecha UTC';Mono=$true},
        @{P='User';L='Usuario'},
        @{P='Browser';L='Navegador'},
        @{P='Servicio';L='Servicio de IA';Mono=$true;Max=30},
        @{P='Url';L='URL';Mono=$true;Max=58}
    )
    & $add (New-ReportTable -Rows (Get-ReportCsv '46_ai_web_usage').Rows -Columns $colAiWeb -MaxRows 300 -SourceCsv '46_ai_web_usage.csv' -EmptyText 'No se detectaron URLs de servicios de IA en el historial preservado.')
    & $add '<h3>URLs de navegaci&#243;n (nube/transferencia y otras)</h3>'
    $colUrls = @(
        @{P='User';L='Usuario'},
        @{P='Browser';L='Navegador'},
        @{P='Category';L='Categoria'},
        @{P='Url';L='URL';Mono=$true;Max=84}
    )
    & $add (New-ReportTable -Rows @((Get-ReportCsv '45_browser_urls').Rows | Where-Object { $_.Category -ne 'Otro' }) -Columns $colUrls -MaxRows 300 -SourceCsv '45_browser_urls.csv' -EmptyText 'Sin URLs de nube/IA en el historial (o navegadores sin historial accesible).')
    & $add '<div class="callout"><p>Cuando el sistema dispone de <span class="mono">winsqlite3</span> (Windows 10/11, Server 2016+), el historial se parsea <b>en vivo con fecha por visita</b> (tablas de arriba). La tabla inferior de URLs sin fecha es la extracci&#243;n <b>best-effort</b> complementaria (por si alguna base estaba bloqueada). Las bases SQLite se preservan &#237;ntegras en <span class="mono">02_Raw_Evidence</span> para reproducir el an&#225;lisis. El historial de <b>navegaci&#243;n privada/inc&#243;gnito no se almacena</b> en estas bases: solo podr&#237;a quedar rastro residual en memoria, WAL, DNS cache o SRUM, y su recuperaci&#243;n no est&#225; garantizada; su ausencia aqu&#237; no prueba que no existiera.</p></div>'
    & $add '</section>'

    
    & $add '<section id="secD"><h2><span class="sn">&#167;D</span>Gesti&#243;n de cuentas y grupos</h2>'
    & $add '<p class="lead">Altas, bajas y modificaciones de cuentas y de pertenencia a grupos (posible creaci&#243;n de usuarios ocultos o escalada de privilegios).</p>'
    if ($secBig) { & $add $secBigNote }
    else {
        $acct = Select-ByEventId -Rows $secRows -Ids @(4720,4722,4723,4724,4725,4726,4738,4740,4767,4781,4728,4729,4732,4733,4756,4757,4735)
        & $add (New-ReportTable -Rows $acct -Columns $colEvtBase -MaxRows 200 -SourceCsv '20_security_events.csv' -EmptyText 'Sin eventos de gesti&#243;n de cuentas/grupos en el periodo.')
    }
    & $add '</section>'

    
    & $add '<section id="secP"><h2><span class="sn">&#167;P</span>Actividad de contrase&#241;as, cuentas y grupos</h2>'
    & $add '<p class="lead">Cambios y restablecimientos de contrase&#241;a, ciclo de vida de cuentas y cambios de pertenencia a grupos (dominio o local), con actor, objetivo, SID, hora e IP de la sesi&#243;n asociada. Incluye los <b>comandos</b> de gesti&#243;n de contrase&#241;as/grupos (con las contrase&#241;as en claro <b>redactadas</b>) y el estado actual de las cuentas locales.</p>'
    & $add '<h3>Eventos de contrase&#241;a y de cuenta</h3>'
    $colPw = @(
        @{P='TimestampUTC';L='Fecha UTC';Mono=$true},
        @{P='EventId';L='ID';Mono=$true},
        @{P='Action';L='Accion';Max=44},
        @{P='ActorUser';L='Actor (quien)'},
        @{P='TargetUser';L='Objetivo (a quien)'},
        @{P='SourceIP';L='IP';Mono=$true},
        @{P='IPSource';L='Origen de la IP';Max=34}
    )
    & $add (New-ReportTable -Rows (Get-ReportCsv '82_password_account_events').Rows -Columns $colPw -MaxRows 300 -SourceCsv '82_password_account_events.csv' -EmptyText 'Sin eventos de contrase&#241;a/cuenta (auditoria de gestion de cuentas desactivada o sin Security).')
    & $add '<h3>Cambios de pertenencia a grupos</h3>'
    $colGrp = @(
        @{P='TimestampUTC';L='Fecha UTC';Mono=$true},
        @{P='EventId';L='ID';Mono=$true},
        @{P='Action';L='Accion';Max=44},
        @{P='ActorUser';L='Actor'},
        @{P='Group';L='Grupo'},
        @{P='Member';L='Miembro';Max=40},
        @{P='SourceIP';L='IP';Mono=$true}
    )
    & $add (New-ReportTable -Rows (Get-ReportCsv '84_group_membership_events').Rows -Columns $colGrp -MaxRows 300 -SourceCsv '84_group_membership_events.csv' -EmptyText 'Sin cambios de pertenencia a grupos en el periodo.')
    & $add '<h3>Comandos de contrase&#241;a/grupo (contrase&#241;as redactadas)</h3>'
    $colCmd = @(
        @{P='TimestampUTC';L='Fecha UTC';Mono=$true},
        @{P='Source';L='Fuente';Max=34},
        @{P='TargetUser';L='Usuario objetivo'},
        @{P='ContienePosibleContrasena';L='Contrasena?'},
        @{P='Command';L='Comando (redactado)';Mono=$true;Max=90}
    )
    & $add (New-ReportTable -Rows (Get-ReportCsv '85_password_group_commands').Rows -Columns $colCmd -MaxRows 200 -SourceCsv '85_password_group_commands.csv' -EmptyText 'Sin comandos de gestion de contrasenas/grupos hallados.')
    & $add '<h3>Estado actual de contrase&#241;as (cuentas locales)</h3>'
    $colSt = @(
        @{P='Name';L='Cuenta'},
        @{P='Enabled';L='Habilitada'},
        @{P='PasswordLastSetUTC';L='Contrasena fijada (UTC)';Mono=$true},
        @{P='PasswordExpiresUTC';L='Expira (UTC)';Mono=$true},
        @{P='LastLogonUTC';L='Ultimo inicio (UTC)';Mono=$true},
        @{P='SID';L='SID';Mono=$true;Max=30}
    )
    & $add (New-ReportTable -Rows (Get-ReportCsv '86_local_account_password_state').Rows -Columns $colSt -MaxRows 100 -SourceCsv '86_local_account_password_state.csv' -EmptyText 'Sin datos de cuentas locales.')
    & $add '<div class="callout"><p>La columna <b>Origen de la IP</b> indica la procedencia del dato, no un mensaje de error: <b>Directa (evento)</b> = la IP consta en el propio registro; <b>Correlacionada</b> = deducida enlazando con el inicio de sesi&#243;n (4624) del mismo actor; <b>No registrada por este evento</b> = Windows no incluye IP en este tipo de evento (los 4724/4738 de cambio de cuenta no la contienen). El <b>historial de contrase&#241;as de cuentas de dominio</b> se consulta en el controlador de dominio (eventos del DC y atributos de AD), no en el endpoint. Las contrase&#241;as en claro de los comandos se han <b>redactado</b>; el detalle bruto y anidado est&#225; en los CSV/JSON de <span class="mono">03_Parsed_Evidence</span>.</p></div>'
    & $add '</section>'

    
    & $add '<section id="secE"><h2><span class="sn">&#167;E</span>Ejecuci&#243;n de procesos y comandos</h2>'
    if (-not $secBig) {
        $proc = Select-ByEventId -Rows $secRows -Ids @(4688)
        $colProc = @(
            @{P='TimestampUTC';L='Fecha UTC';Mono=$true},@{P='TimestampLocal';L='Hora local';Mono=$true},@{P='User';L='Usuario'},
            @{P='ProcessName';L='Proceso';Max=52},@{P='ParentProcessName';L='Proceso padre';Max=38},
            @{P='CommandLine';L='L&#237;nea de comandos';Mono=$true;Max=90},
            @{P='ProcessId';L='PID';Mono=$true},@{P='ParentProcessId';L='PPID';Mono=$true}
        )
        & $add '<h3>Creaci&#243;n de procesos (4688)</h3>'
        & $add '<div class="callout"><p><b>C&#243;mo leer esta tabla:</b> el <b>PID</b> (identificador del proceso) es el n&#250;mero &#250;nico que Windows asigna a cada programa en ejecuci&#243;n; el <b>PPID</b> (identificador del proceso padre) es el del programa que lo lanz&#243;. Encadenar padre&#8594;hijo permite reconstruir qu&#233; abri&#243; qu&#233; (por ejemplo, si <span class="mono">cmd.exe</span> fue lanzado por un proceso inesperado). La <b>l&#237;nea de comandos</b> solo se registra si la auditor&#237;a correspondiente estaba activada; si aparece vac&#237;a, el dato debe buscarse en fuentes complementarias (Sysmon 1, PowerShell, Prefetch, Amcache).</p></div>'
        & $add (New-ReportTable -Rows $proc -Columns $colProc -MaxRows 250 -SourceCsv '20_security_events.csv' -EmptyText 'Sin eventos 4688 (auditor&#237;a de creaci&#243;n de procesos posiblemente deshabilitada; ver Prefetch, Amcache, BAM/DAM y PowerShell como fuentes complementarias).')
    }
    $ps = Get-ReportCsv '22_powershell_events'
    $colPs = @(@{P='TimestampUTC';L='Fecha UTC';Mono=$true},@{P='EventId';L='ID';Mono=$true},@{P='Computer';L='Equipo'},@{P='Notes';L='Bloque de script / detalle';Mono=$true;Max=140})
    & $add '<h3>Actividad de PowerShell</h3>'
    & $add (New-ReportTable -Rows $ps.Rows -Columns $colPs -MaxRows 150 -SourceCsv '22_powershell_events.csv' -EmptyText 'Sin actividad de PowerShell registrada en el periodo.')
    & $add '<h3>Ultima ejecuci&#243;n de programas por usuario (BAM/DAM) &#8212; con fecha</h3>'
    & $add '<p class="muted">BAM/DAM registra, por cuenta de usuario, la <b>&#250;ltima vez</b> que se ejecut&#243; cada programa (con fecha). Complementa a UserAssist y Prefetch para atribuir ejecuciones a una <b>cuenta de usuario</b> en el tiempo.</p>'
    $colBam = @(
        @{P='LastRunUTC';L='Ultima ejecucion (UTC)';Mono=$true},
        @{P='User';L='Usuario'},
        @{P='Program';L='Programa';Mono=$true;Max=74},
        @{P='Source';L='Fuente'}
    )
    & $add (New-ReportTable -Rows (Get-ReportCsv '43_program_execution_bam').Rows -Columns $colBam -MaxRows 400 -SourceCsv '43_program_execution_bam.csv' -EmptyText 'Sin datos BAM/DAM (Windows sin BAM o sin privilegios).')
    & $add '<h3>Procesos en ejecuci&#243;n (instant&#225;nea de adquisici&#243;n)</h3>'
    $colProc60 = @(
        @{P='ProcessId';L='PID';Mono=$true},
        @{P='ParentProcessId';L='PPID';Mono=$true},
        @{P='ProcessName';L='Proceso'},
        @{P='ExecutablePath';L='Ruta del ejecutable';Mono=$true;Max=50},
        @{P='CommandLine';L='Linea de comandos';Mono=$true;Max=76},
        @{P='Owner';L='Usuario'},
        @{P='Signature';L='Firma'},
        @{P='ExeSHA256';L='SHA-256';Mono=$true;Max=20},
        @{P='CreatedUTC';L='Creado (UTC)';Mono=$true}
    )
    & $add (New-ReportTable -Rows (Get-ReportCsv '60_running_processes').Rows -Columns $colProc60 -MaxRows 300 -SourceCsv '60_running_processes.csv')
    & $add '</section>'

    
    & $add '<section id="secF"><h2><span class="sn">&#167;F</span>Accesos remotos y movimiento lateral</h2>'
    & $add '<p class="lead">Conexiones remotas entrantes (RDP y otros) con <b>usuario, IP de origen, tipo y hora</b>. Si el acceso es directo desde Internet, la IP de origen es la <b>IP p&#250;blica del cliente</b>; si viene de la red interna, ser&#225; una IP privada.</p>'
    $colRS = @(
        @{P='TimestampUTC';L='Fecha UTC (+0)';Mono=$true},
        @{P='TimestampLocal';L='Hora local (+2)';Mono=$true},
        @{P='User';L='Usuario'},
        @{P='SourceIP';L='IP de origen';Mono=$true},
        @{P='SessionType';L='Tipo de evento';Max=32}
    )
    & $add (New-ReportTable -Rows (Get-ReportCsv '26_remote_sessions').Rows -Columns $colRS -MaxRows 500 -SourceCsv '26_remote_sessions.csv' -EmptyText 'Sin sesiones RDP entrantes registradas en el periodo (revisar tambien inicios de sesion remotos en el apartado C).')
    
    $sessTL = Get-ReportCsv '29_rdp_session_timeline'
    if ($sessTL.Rows.Count -gt 0) {
        & $add '<h3>Cronolog&#237;a de sesiones RDP (reconstruida)</h3>'
        & $add '<p class="muted">Cada fila agrupa los eventos de una misma sesi&#243;n (por SessionId): qui&#233;n se conect&#243;, desde qu&#233; IP, cu&#225;ndo empez&#243; y c&#243;mo termin&#243;. Reconstruye la secuencia Origen &#8594; Usuario &#8594; Conexi&#243;n &#8594; Cierre a partir de los eventos 1149/21/22/23/24/25/40.</p>'
        $colSess = @(
            @{P='InicioUTC';L='Inicio (UTC)';Mono=$true},
            @{P='InicioLocal';L='Inicio (local)';Mono=$true},
            @{P='SessionId';L='Sesion';Mono=$true},
            @{P='Usuario';L='Usuario'},
            @{P='IpOrigen';L='IP origen';Mono=$true},
            @{P='Conexion';L='Conexion';Max=30},
            @{P='DuracionMin';L='Duracion (min)';Mono=$true},
            @{P='Cierre';L='Cierre';Max=40}
        )
        & $add (New-ReportTable -Rows $sessTL.Rows -Columns $colSess -MaxRows 150 -SourceCsv '29_rdp_session_timeline.csv' -EmptyText 'Sin sesiones RDP reconstruidas.')
    }
    $colRdp = @(@{P='TimestampUTC';L='Fecha UTC';Mono=$true},@{P='TimestampLocal';L='Hora local';Mono=$true},@{P='EventId';L='ID';Mono=$true},@{P='User';L='Usuario'},@{P='SourceIP';L='IP origen';Mono=$true},@{P='Notes';L='Detalle';Max=80})
    & $add '<h3>RDP entrante &#8212; gestor de sesiones (LSM 21-40) y de conexiones (RCM 1149)</h3>'
    & $add '<p class="muted">Eventos individuales. No todos llevan IP de origen: solo la <b>conexi&#243;n inicial</b> (1149) y la <b>reconexi&#243;n</b> (25) registran la direcci&#243;n del cliente; los eventos de sesi&#243;n/cierre (21/22/23/24/40) identifican usuario y sesi&#243;n pero no repiten la IP. La cronolog&#237;a de arriba correlaciona ambos.</p>'
    & $add (New-ReportTable -Rows ((Get-ReportCsv '25_rdp_rcm_events').Rows) -Columns $colRdp -MaxRows 120 -SourceCsv '25_rdp_rcm_events.csv')
    & $add (New-ReportTable -Rows ((Get-ReportCsv '24_rdp_lsm_events').Rows) -Columns $colRdp -MaxRows 120 -SourceCsv '24_rdp_lsm_events.csv')
    & $add '<h3>RDP saliente (RDPClient 1024/1102) y WinRM (28)</h3>'
    & $add '<p class="muted">RDP <b>saliente</b>: conexiones iniciadas DESDE este equipo hacia otro (1024 = nombre del servidor destino; 1102 = direcci&#243;n del servidor destino). La IP/nombre que aparece es el <b>destino</b>, no el origen.</p>'
    & $add (New-ReportTable -Rows ((Get-ReportCsv '27_rdp_outbound_events').Rows) -Columns $colRdp -MaxRows 120 -SourceCsv '27_rdp_outbound_events.csv')
    & $add (New-ReportTable -Rows ((Get-ReportCsv '28_winrm_events').Rows) -Columns $colRdp -MaxRows 120 -SourceCsv '28_winrm_events.csv')
    if (-not $secBig) {
        & $add '<h3>Acceso a recursos compartidos (SMB: 5140/5142/5145)</h3>'
        $smb = Select-ByEventId -Rows $secRows -Ids @(5140,5142,5145)
        & $add (New-ReportTable -Rows $smb -Columns $colEvtBase -MaxRows 200 -SourceCsv '20_security_events.csv' -EmptyText 'Sin accesos SMB auditados en el periodo.')
    }
    & $add '<h3>Herramientas de control remoto detectadas</h3>'
    & $add '<div class="callout"><p>La presencia no acredita uso. Correlaci&#243;nese con procesos, sesiones y marcas temporales.</p></div>'
    & $add (New-ReportTable -Rows (Get-ReportCsv '50_remote_tools_detection').Rows -MaxRows 100 -SourceCsv '50_remote_tools_detection.csv' -EmptyText 'No se detectaron herramientas de control remoto de terceros.')
    & $add '</section>'

    
    & $add '<section id="secT"><h2><span class="sn">&#167;T</span>Inicios de sesi&#243;n en el periodo analizado y correlaci&#243;n</h2>'
    & $add '<p class="lead">Se muestra <b>primero y por separado</b> lo ocurrido <b>dentro de la ventana temporal analizada</b> (accesos correctos e intentos fallidos, cada uno con su IP y su equipo de origen), y despu&#233;s la comparaci&#243;n con el historial previo. As&#237; se distingue con claridad <b>qui&#233;n inici&#243; sesi&#243;n</b> de <b>qui&#233;n solo lo intent&#243;</b>, y <b>desde d&#243;nde</b>, en ese periodo.</p>'

    & $add '<div class="callout"><p><b>Nota sobre el filtrado:</b> estas tablas muestran los inicios de sesi&#243;n <b>humanos</b> (interactivos, de red y RDP). Se excluyen los inicios de <b>servicios y del sistema</b> (SYSTEM, tipo 5, cuentas DWM/UMFD, cuentas de m&#225;quina), muy numerosos y sin valor para la atribuci&#243;n; su detalle se conserva en <span class="mono">57_logon_system_service_during_attack.csv</span>. Muchos inicios locales/servicio no llevan IP por su naturaleza.</p></div>'
    & $add '<h3>1) Accesos CORRECTOS en el periodo analizado</h3>'
    & $add '<p class="muted">Sesiones que <b>s&#237; se iniciaron</b> (evento 4624 / RDP) dentro de la ventana. Cada fila es un acceso con su IP y equipo de origen.</p>'
    $colNight = @(
        @{P='HoraLocal';L='Hora local';Mono=$true},
        @{P='HoraUTC';L='Hora UTC';Mono=$true},
        @{P='Usuario';L='Usuario'},
        @{P='IP';L='IP de origen';Mono=$true},
        @{P='Estacion';L='Estacion (equipo origen)';Mono=$true;Max=24},
        @{P='Tipo';L='Tipo de inicio';Max=30},
        @{P='Fuente';L='Fuente';Mono=$true}
    )
    & $add (New-ReportTable -Rows (Get-ReportCsv '54_logon_ok_during_attack').Rows -Columns $colNight -MaxRows 400 -SourceCsv '54_logon_ok_during_attack.csv' -EmptyText 'No consta ning&#250;n acceso CORRECTO dentro de la ventana temporal analizada.')

    & $add '<h3>2) Intentos FALLIDOS en el periodo analizado</h3>'
    & $add '<p class="muted">Intentos que <b>no lograron</b> iniciar sesi&#243;n (evento 4625) dentro de la ventana. Un fallido NO significa acceso; para saber si entr&#243;, b&#250;squese la misma IP/estaci&#243;n en la tabla anterior.</p>'
    & $add (New-ReportTable -Rows (Get-ReportCsv '55_logon_fail_during_attack').Rows -Columns $colNight -MaxRows 500 -SourceCsv '55_logon_fail_during_attack.csv' -EmptyText 'No consta ning&#250;n intento fallido dentro de la ventana temporal analizada.')

    & $add '<h3>3) Recuento por equipo de origen (en el periodo analizado)</h3>'
    & $add '<p class="muted">Desde qu&#233; equipos se originaron los intentos y cu&#225;ntos. Un recuento alto de fallidos es compatible con fuerza bruta o prueba masiva de cuentas.</p>'
    $colSt = @(
        @{P='Estacion';L='Estacion (equipo origen)'},
        @{P='Intentos';L='Intentos totales';Mono=$true},
        @{P='Correctos';L='Correctos';Mono=$true},
        @{P='Fallidos';L='Fallidos';Mono=$true},
        @{P='Usuarios';L='Usuarios probados';Max=50}
    )
    & $add (New-ReportTable -Rows (Get-ReportCsv '56_station_counts_during_attack').Rows -Columns $colSt -MaxRows 100 -SourceCsv '56_station_counts_during_attack.csv' -EmptyText 'Sin actividad de inicio de sesion en la ventana.')

    & $add '<h3>4) Mapa por usuario: IP del periodo analizado vs. IP habitual</h3>'
    & $add '<p class="muted">Por cada cuenta se separa la <b>IP/estaci&#243;n usada en el periodo analizado</b> de las <b>IP habituales previas</b>, para no confundirlas.</p>'
    $colMap = @(
        @{P='Usuario';L='Usuario'},
        @{P='IniciosCorrectos';L='Correctos';Mono=$true},
        @{P='IntentosFallidos';L='Fallidos';Mono=$true},
        @{P='IpEsaNoche';L='IP en el periodo';Mono=$true;Max=28},
        @{P='EstacionEsaNoche';L='Estacion en el periodo';Mono=$true;Max=24},
        @{P='IpHabitual';L='IP habitual (antes)';Mono=$true;Max=28}
    )
    & $add (New-ReportTable -Rows (Get-ReportCsv '53_logon_map').Rows -Columns $colMap -MaxRows 200 -SourceCsv '53_logon_map.csv' -EmptyText 'Sin inicios de sesion en el periodo recogido.')

    & $add '<h3>5) Correlaci&#243;n de origen: IP del periodo analizado frente al hist&#243;rico previo</h3>'
    & $add '<p class="muted">Se contrasta cada IP observada en el periodo analizado con el hist&#243;rico previo del propio equipo. La columna <b>D&#237;as desde la &#250;ltima vez</b> mide el tiempo entre la &#250;ltima aparici&#243;n de esa IP <b>antes</b> del periodo y el inicio del periodo; solo cuenta como hist&#243;rico previo lo estrictamente anterior. Una IP recurrente (ya utilizada meses antes) es indicativa de un mismo origen de conexi&#243;n. Una IP que aparece <b>solo</b> en el periodo no es necesariamente an&#243;mala si el hist&#243;rico conservado es escaso: la valoraci&#243;n lo indica.</p>'
    $colIpc = @(
        @{P='IP';L='IP de origen';Mono=$true},
        @{P='Tipo';L='Tipo'},
        @{P='VecesEnElAtaque';L='Veces (periodo)';Mono=$true},
        @{P='VecesAntes';L='Veces (antes)';Mono=$true},
        @{P='LastSeenBeforePeriodUTC';L='Ultima vez antes (UTC)';Mono=$true},
        @{P='DiasAntesDelAtaque';L='Dias desde la ultima vez';Mono=$true},
        @{P='EstacionesEnPeriodo';L='Estacion (periodo)';Mono=$true;Max=20},
        @{P='Correlacion';L='Valoracion';Max=44}
    )
    & $add (New-ReportTable -Rows (Get-ReportCsv '52_logon_ip_correlation').Rows -Columns $colIpc -MaxRows 300 -SourceCsv '52_logon_ip_correlation.csv' -EmptyText 'Sin datos de correlacion (ejecutar con rango amplio -StartDate y con -IncidentStart/-IncidentEnd).')

    & $add '<div class="anexo"><h4>Anexo de esta secci&#243;n: c&#243;digos e IDs</h4>'
    & $add '<p><b>Estaci&#243;n</b> = nombre del equipo de ORIGEN del intento (WorkstationName). <span class="mono">127.0.0.1</span>/nombre propio = el intento se hizo en el propio equipo analizado; un nombre ajeno (p.ej. LAPTOP-XXXX, B_205) = otra m&#225;quina de la red intent&#243; entrar A este equipo.</p>'
    & $add '<table><tr><th>Evento</th><th>Significado</th></tr>'
    & $add '<tr><td>4624</td><td>Inicio de sesion CORRECTO</td></tr><tr><td>4625</td><td>Intento de inicio de sesion FALLIDO</td></tr>'
    & $add '<tr><td>1149</td><td>Autenticacion RDP correcta (trae usuario e IP)</td></tr>'
    & $add '<tr><td>21 / 22</td><td>Inicio de sesion RDP / carga del escritorio</td></tr>'
    & $add '<tr><td>25</td><td>Reconexion a una sesion RDP desconectada</td></tr>'
    & $add '<tr><td>24</td><td>Desconexion RDP (deja la sesion abierta)</td></tr>'
    & $add '<tr><td>23</td><td>Cierre de sesion RDP completo</td></tr>'
    & $add '<tr><td>39 / 40</td><td>Sesion desconectada (39: por otra sesion; 40: con motivo)</td></tr></table>'
    & $add '<p><b>Tipo de inicio (Logon Type):</b> 2 Interactivo (teclado local) &#183; 3 Red (SMB) &#183; 5 Servicio &#183; 9 RunAs/netonly &#183; <b>10 Escritorio remoto (RDP)</b> &#183; 11 con credenciales en cache.</p></div>'
    & $add '<div class="callout"><p><b>Requisito para comparar con 6 meses antes:</b> recoger un rango amplio (<span class="mono">-StartDate</span> de hace 6+ meses) y marcar la ventana con <span class="mono">-IncidentStart</span> / <span class="mono">-IncidentEnd</span>. Si Security ya rot&#243;, el hist&#243;rico se obtiene del <b>firewall</b> o de imagen/instant&#225;neas.</p></div>'
    & $add '</section>'

    
    & $add '<section id="secG"><h2><span class="sn">&#167;G</span>Persistencia (tareas, servicios, WMI)</h2>'
    & $add '<h3>Tareas programadas (eventos)</h3>'
    & $add (New-ReportTable -Rows (Get-ReportCsv '23_taskscheduler_events').Rows -Columns $colEvtBase -MaxRows 120 -SourceCsv '23_taskscheduler_events.csv')
    & $add '<h3>Servicios</h3>'
    & $add '<p class="muted">La columna <b>Evaluaci&#243;n de ruta</b> marca como INDICADOR los servicios cuyo ejecutable est&#225; en rutas an&#243;malas (perfil de usuario, Temp, ProgramData o red UNC): es una se&#241;al de triaje para revisar, <b>no</b> un veredicto de malicia.</p>'
    & $add '<p class="muted">La columna <b>Instalado</b> muestra la fecha en que se registr&#243; el servicio (correlacionada con el evento System 7045 / Security 4697), cuando consta; permite detectar servicios creados durante el periodo de inter&#233;s.</p>'
    $colSvc = @(
        @{P='InstaladoUTC';L='Instalado (UTC)';Mono=$true},
        @{P='Name';L='Servicio'},
        @{P='DisplayName';L='Nombre visible';Max=28},
        @{P='State';L='Estado'},
        @{P='StartMode';L='Inicio'},
        @{P='StartName';L='Cuenta';Max=18},
        @{P='PathName';L='Ejecutable';Mono=$true;Max=44},
        @{P='PathAssessment';L='Evaluacion de ruta';Max=34}
    )
    
    $svcRows = @(Get-ReportCsv '70_services').Rows
    $svcSorted = @($svcRows | Sort-Object @{E={[bool]$_.InstaladoUTC};D=$true}, @{E={$_.SuspiciousPathFlag -eq 'True'};D=$true})
    & $add (New-ReportTable -Rows $svcSorted -Columns $colSvc -MaxRows 300 -SourceCsv '70_services.csv')
    & $add '<h3>Suscripciones permanentes de WMI</h3>'
    & $add '<p class="muted">Las suscripciones WMI permanentes (Filter + Consumer + Binding) son un vector de persistencia sigilosa: un <b>Filter</b> define el disparador (una consulta WQL), un <b>Consumer</b> la acci&#243;n (comando o script), y el <b>Binding</b> los une. Se muestra la consulta y el comando/script de cada uno.</p>'
    $colWmi = @(
        @{P='Type';L='Tipo';Max=10},
        @{P='Name';L='Nombre';Max=24},
        @{P='Query';L='Consulta (Filter)';Mono=$true;Max=40},
        @{P='CommandOrScript';L='Comando/Script (Consumer)';Mono=$true;Max=44},
        @{P='Detail';L='Detalle';Max=40}
    )
    & $add (New-ReportTable -Rows (Get-ReportCsv '71_wmi_subscriptions').Rows -Columns $colWmi -MaxRows 60 -SourceCsv '71_wmi_subscriptions.csv' -EmptyText 'Sin suscripciones WMI permanentes (vector de persistencia sigilosa).')
    & $add '</section>'

    
    & $add '<section id="secH"><h2><span class="sn">&#167;H</span>Red y conexiones</h2>'
    & $add '<h3>Conexiones TCP (instant&#225;nea)</h3>'
    & $add '<p class="muted">Cada conexi&#243;n con su extremo local y remoto, estado, y el <b>proceso</b> (PID, nombre y ruta) que la mantiene, para poder atribuir una conexi&#243;n saliente a un programa concreto.</p>'
    $colTcp = @(
        @{P='LocalEndpoint';L='Local (IP:puerto)';Mono=$true},
        @{P='RemoteEndpoint';L='Remoto (IP:puerto)';Mono=$true},
        @{P='State';L='Estado'},
        @{P='OwningProcess';L='PID';Mono=$true},
        @{P='ProcessName';L='Proceso'},
        @{P='ProcessPath';L='Ruta del proceso';Mono=$true;Max=46}
    )
    & $add (New-ReportTable -Rows (Get-ReportCsv '51_tcp_connections').Rows -Columns $colTcp -MaxRows 400 -SourceCsv '51_tcp_connections.csv')
    & $add '<div class="callout"><p>Configuraci&#243;n de red, DNS, rutas, ARP, cortafuegos, proxy y recursos compartidos se conservan &#237;ntegros en <span class="mono">03_Parsed_Evidence\TXT</span> (ipconfig, netstat, netsh, net).</p></div>'
    & $add '</section>'

    
    & $add '<section id="secI"><h2><span class="sn">&#167;I</span>Artefactos de archivos y borrado</h2>'
    & $add '<h3>Evidencia de ejecuci&#243;n (Prefetch)</h3>'
    & $add (New-ReportTable -Rows (Get-ReportCsv '40_prefetch_metadata').Rows -MaxRows 200 -SourceCsv '40_prefetch_metadata.csv')
    & $add '<h3>Papelera de reciclaje (metadatos)</h3>'
    & $add (New-ReportTable -Rows (Get-ReportCsv '41_recyclebin_metadata').Rows -MaxRows 200 -SourceCsv '41_recyclebin_metadata.csv' -EmptyText 'Sin elementos en la papelera con metadatos recuperables.')
    & $add '<h3>L&#237;nea temporal de archivos (MACB) en el periodo</h3>'
    & $add '<p class="muted"><b>MACB</b> son las cuatro marcas de tiempo NTFS de cada archivo: <b>M</b>odificado (contenido), <b>A</b>ccedido (&#250;ltimo acceso), <b>C</b>ambio de metadatos (MFT) y <b>B</b>=creaci&#243;n (born). Permite ver qu&#233; archivos se crearon o modificaron en el periodo. El &#250;ltimo acceso s&#243;lo es fiable si el sistema no tiene deshabilitada su actualizaci&#243;n.</p>'
    $colMacb = @(
        @{P='FilePath';L='Archivo';Mono=$true;Max=60},
        @{P='SizeBytes';L='Bytes';Mono=$true},
        @{P='CreatedUTC';L='Creado B (UTC)';Mono=$true},
        @{P='ModifiedUTC';L='Modificado M (UTC)';Mono=$true},
        @{P='AccessedUTC';L='Accedido A (UTC)';Mono=$true},
        @{P='Owner';L='Propietario';Max=28}
    )
    & $add (New-ReportTable -Rows (Get-ReportCsv '42_file_timeline_macb').Rows -Columns $colMacb -MaxRows 400 -SourceCsv '42_file_timeline_macb.csv')
    & $add '<h3>Origen de descarga de archivos (Mark-of-the-Web / Zone.Identifier)</h3>'
    & $add '<p class="muted">NTFS marca los archivos descargados con un flujo <span class="mono">Zone.Identifier</span> que guarda <b>de d&#243;nde procede</b> el archivo (URL de origen y referente). Es una evidencia directa de entrada de datos desde Internet.</p>'
    & $add '<p class="muted">La <b>fecha</b> mostrada es el <span class="mono">LastWrite</span> del archivo, <b>aproximada</b> al momento de descarga (no exacta): la datacion precisa se correlaciona con el historial del navegador, el USN o Prefetch.</p>'
    $colDl = @(
        @{P='TimestampUTC';L='Fecha (aprox.)';Mono=$true},
        @{P='FilePath';L='Archivo';Mono=$true;Max=44},
        @{P='Zona';L='Zona'},
        @{P='HostUrl';L='URL de origen';Mono=$true;Max=52},
        @{P='ReferrerUrl';L='Referente';Mono=$true;Max=36}
    )
    & $add (New-ReportTable -Rows (Get-ReportCsv '73_download_origin').Rows -Columns $colDl -MaxRows 400 -SourceCsv '73_download_origin.csv' -EmptyText 'Sin archivos con marca de origen de descarga (Zone.Identifier).')
    & $add '<h3>Flujos de datos alternativos an&#243;malos (ADS)</h3>'
    & $add '<p class="muted">Un <b>ADS</b> es un flujo oculto que NTFS adjunta a un archivo sin verse en el Explorador. Fuera del habitual <span class="mono">Zone.Identifier</span>, un ADS puede usarse para <b>ocultar</b> datos o c&#243;digo: por eso se listan como indicador.</p>'
    $colAds = @(
        @{P='FilePath';L='Archivo';Mono=$true;Max=52},
        @{P='StreamName';L='Flujo';Max=24},
        @{P='StreamLength';L='Bytes';Mono=$true},
        @{P='ContentPreview';L='Vista previa';Max=40},
        @{P='ModifiedUTC';L='Modificado (UTC)';Mono=$true}
    )
    & $add (New-ReportTable -Rows (Get-ReportCsv '72_alternate_data_streams').Rows -Columns $colAds -MaxRows 150 -SourceCsv '72_alternate_data_streams.csv' -EmptyText 'Sin flujos de datos alternativos an&#243;malos (distintos de Zone.Identifier).')
    & $add '<div class="callout"><p>MFT, $LogFile, contenido del USN Journal, ShellBags, SRUM y Amcache se preservan en bruto (02) y requieren an&#225;lisis offline con utilidades espec&#237;ficas.</p></div>'
    & $add '</section>'

    
    & $add '<section id="secO"><h2><span class="sn">&#167;O</span>Archivos eliminados (trazabilidad forense)</h2>'
    & $add '<p class="lead">Reconstrucci&#243;n de la historia de archivos borrados correlacionando m&#250;ltiples artefactos. Se distingue evidencia <b>directa</b> (Papelera $I/$R) de <b>inferida</b> (referencias LNK, comandos de borrado, auditor&#237;a). Cada conclusi&#243;n lleva su nivel de confianza; no se afirma borrado definitivo sin evidencia que lo sustente.</p>'
    & $add '<h3>Archivos con evidencia de eliminaci&#243;n</h3>'
    $colDF = @(
        @{P='Name';L='Archivo'},
        @{P='OriginalPath';L='Ruta original';Mono=$true;Max=58},
        @{P='User';L='Usuario'},
        @{P='DeletedUTC';L='Borrado (UTC)';Mono=$true},
        @{P='DeletionMethod';L='Metodo';Max=38},
        @{P='Status';L='Estado'},
        @{P='Recoverability';L='Recuperab.'},
        @{P='Confidence';L='Confianza'}
    )
    & $add (New-ReportTable -Rows (Get-ReportCsv '95_deleted_files').Rows -Columns $colDF -MaxRows 300 -SourceCsv '95_deleted_files.csv' -EmptyText 'No se hall&#243; evidencia de archivos eliminados en las fuentes disponibles en vivo.')
    & $add '<h3>Cronolog&#237;a de eventos de borrado</h3>'
    $colDFT = @(
        @{P='TimestampUTC';L='Fecha UTC';Mono=$true},
        @{P='Event';L='Evento'},
        @{P='File';L='Archivo'},
        @{P='Path';L='Ruta';Mono=$true;Max=52},
        @{P='User';L='Usuario'},
        @{P='Source';L='Fuente'},
        @{P='Confidence';L='Confianza'}
    )
    & $add (New-ReportTable -Rows (Get-ReportCsv '96_deleted_files_timeline').Rows -Columns $colDFT -MaxRows 400 -SourceCsv '96_deleted_files_timeline.csv' -EmptyText 'Sin eventos de borrado datables en las fuentes en vivo.')
    & $add '<h3>Instant&#225;neas de volumen (VSS) &#8212; puntos de recuperaci&#243;n</h3>'
    & $add '<p class="muted">Cada instant&#225;nea conserva el estado del disco en su fecha, <b>incluidos archivos que despu&#233;s se borraron</b>. Son la v&#237;a para recuperar hechos anteriores a la ventana del USN: se montan y analizan en fr&#237;o.</p>'
    $colVss = @(
        @{P='CreationLocal';L='Fecha de creacion';Mono=$true},
        @{P='OriginalVolume';L='Volumen'},
        @{P='State';L='Estado';Max=14},
        @{P='ClientAccessible';L='Accesible';Max=10},
        @{P='Device';L='Dispositivo montable';Mono=$true;Max=44},
        @{P='ShadowId';L='ID de instantanea';Mono=$true;Max=38}
    )
    & $add (New-ReportTable -Rows (Get-ReportCsv '98_vss_snapshots').Rows -Columns $colVss -MaxRows 100 -SourceCsv '98_vss_snapshots.csv' -EmptyText 'Sin instant&#225;neas VSS disponibles: los hechos anteriores a la ventana del USN/Security requieren imagen de disco.')
    & $add '<div class="callout"><p>Confianza: <b>Confirmada</b> (evidencia directa: &#237;ndice $I / contenido $R presentes) &#183; <b>Alta</b> (varias fuentes independientes o auditor&#237;a 4660) &#183; <b>Probable</b> &#183; <b>Posible</b> &#183; <b>Indeterminada</b>. El detalle con evidencias por archivo est&#225; en <span class="mono">03_Parsed_Evidence\JSON\95_deleted_files_detailed.json</span>. La reconstrucci&#243;n exhaustiva de contenido y tiempos ($MFT, $UsnJrnl, $LogFile) y la recuperaci&#243;n desde instant&#225;neas VSS se realizan sobre imagen forense/offline; el USN se preserva parcialmente en <span class="mono">02_Raw_Evidence\DeletedFiles</span>.</p></div>'
    & $add '</section>'

    
    & $add '<section id="secJ"><h2><span class="sn">&#167;J</span>Antiforensia y estado de la defensa</h2>'
    & $add '<div class="callout"><p><b>C&#243;mo interpretar esta secci&#243;n:</b> <span class="mono">1102</span> = se borr&#243; el registro de Seguridad; <span class="mono">104</span> = se borr&#243; un registro operativo (System u otro); <span class="mono">4719</span> = se cambi&#243; la pol&#237;tica de auditor&#237;a (puede usarse para dejar de registrar). La presencia de estos eventos es un <b>indicio fuerte</b> de manipulaci&#243;n de la evidencia; su <b>ausencia no prueba</b> que no se borrara nada (un borrado hecho offline o el propio 1102 pueden no dejar rastro en el log vivo). Cada evento incluye, cuando existe, la cuenta que lo origin&#243;.</p></div>'
    if (-not $secBig) {
        & $add '<h3>Borrado de registros y cambios de auditor&#237;a</h3>'
        $anti = Select-ByEventId -Rows $secRows -Ids @(1102,4719,4817,4906,4907,4908,4912)
        & $add (New-ReportTable -Rows $anti -Columns $colEvtBase -MaxRows 120 -SourceCsv '20_security_events.csv' -EmptyText 'No se detect&#243; borrado del registro de Seguridad (1102) ni cambios de pol&#237;tica de auditor&#237;a (4719) en la ventana conservada. Recuerde: la ausencia no prueba que no ocurriera (posible borrado offline o log rotado).')
    }
    $sysEv = Get-ReportCsv '21_system_events'
    $logclr = Select-ByEventId -Rows $sysEv.Rows -Ids @(104)
    & $add '<h3>Borrado de registros operativos (System 104)</h3>'
    & $add (New-ReportTable -Rows $logclr -Columns $colEvtBase -MaxRows 60 -SourceCsv '21_system_events.csv' -EmptyText 'Sin borrado de registros operativos detectado.')
    & $add '<h3>Estado de Windows Defender</h3>'
    $def = Get-ReportCsv '80_defender_status'
    if ($def.Rows.Count -gt 0) { & $add (New-KeyValueTable -Row $def.Rows[0]) } else { & $add '<p class="empty">Estado de Defender no disponible.</p>' }
    & $add '<h3>Exclusiones configuradas</h3>'
    & $add '<p class="muted">Una exclusi&#243;n amplia puede indicar preparaci&#243;n de evasi&#243;n (indicador).</p>'
    & $add (New-ReportTable -Rows (Get-ReportCsv '81_defender_exclusions').Rows -MaxRows 100 -SourceCsv '81_defender_exclusions.csv' -EmptyText 'Sin exclusiones configuradas (o no accesibles).')
    & $add '</section>'

    
    & $add '<section id="secK"><h2><span class="sn">&#167;K</span>Herramientas de inteligencia artificial</h2>'
    & $add '<div class="notice"><p><b>Advertencia pericial:</b> la presencia de estas herramientas <b>no acredita su uso ni la autor&#237;a</b> de acci&#243;n alguna. Cualquier atribuci&#243;n exige correlaci&#243;n con eventos de creaci&#243;n de proceso, historiales y marcas temporales.</p></div>'
    & $add '<p class="muted">Detecci&#243;n <b>multicriterio</b>: cada hallazgo indica su <b>tipo</b> (aplicaci&#243;n instalada, extensi&#243;n de IDE, o servicio usado por navegador), la <b>fuente</b> de la que procede y un <b>nivel de confianza</b>. Solo se listan detecciones reales (no ausencias). Un hallazgo de confianza <b>Media</b> o inferior no debe presentarse como hecho confirmado.</p>'
    $colAI = @(
        @{P='Confidence';L='Confianza';Max=10},
        @{P='Tipo';L='Tipo';Max=30},
        @{P='Producto';L='Producto/Servicio';Max=26},
        @{P='EvidenceSource';L='Fuente de la evidencia';Max=38},
        @{P='DetectionReason';L='Motivo de deteccion';Mono=$true;Max=52}
    )
    & $add (New-ReportTable -Rows (Get-ReportCsv '90_ai_tools_detection').Rows -Columns $colAI -MaxRows 200 -SourceCsv '90_ai_tools_detection.csv' -EmptyText 'No se detectaron clientes/agentes de IA, extensiones ni uso de servicios de IA por web en los perfiles analizados.')
    & $add '<div class="callout"><p>Categor&#237;as: <b>Aplicaci&#243;n IA instalada</b> (directorio de cliente en el perfil &#8594; confianza Alta de instalaci&#243;n); <b>Extensi&#243;n de IDE</b> (VS Code &#8594; instalada, uso no acreditado); <b>Servicio de IA usado por navegador</b> (URL en el historial &#8594; Alta si hay fecha de visita, Media si solo consta la URL). En todos los casos: la presencia o el acceso <b>no acredita la autor&#237;a</b> personal; esta requiere correlaci&#243;n con procesos (4688/Sysmon), historiales de shell y la sesi&#243;n de usuario.</p></div>'
    & $add '</section>'

    
    & $add '<section id="secL"><h2><span class="sn">&#167;L</span>Integridad de la evidencia</h2>'
    & $add ('<p class="lead">Cada evidencia se sella con SHA-256 en el momento de la copia y se reverifica al finalizar. Resultado: <b>' + $matchCount + '</b> verificadas, <b>' + $mismatchCount + '</b> divergencias sobre ' + $script:EvidenceList.Count + ' evidencias.</p>')
    $colEv = @(@{P='Category';L='Categor&#237;a'},@{P='RelativePath';L='Archivo';Mono=$true;Max=70},@{P='SizeBytes';L='Bytes';Mono=$true},@{P='SHA256';L='SHA-256';Mono=$true;Max=32},@{P='VerifiedAtEnd';L='Verificaci&#243;n';Max=60})
    
    $evOrdered = @($script:EvidenceList | Sort-Object @{E={ $v=[string]$_.VerifiedAtEnd; if ($v -like 'MISMATCH*') { 0 } elseif ($v -like 'VOLATIL*') { 1 } elseif ($v -like 'RESELLADO*') { 2 } elseif ($v -eq 'NOT_APPLICABLE') { 3 } else { 4 } }}, RelativePath)
    $nMis = @($script:EvidenceList | Where-Object { $_.VerifiedAtEnd -like 'MISMATCH*' }).Count
    if ($nMis -gt 0) { & $add ('<div class="notice"><p><b>Atenci&#243;n:</b> ' + $nMis + ' evidencia(s) con hash divergente. Se listan en las primeras filas de la tabla. Una divergencia en <span class="mono">02_Raw_Evidence</span> exige revisar la copia; en productos del script indica actualizaci&#243;n posterior al primer sellado.</p></div>') }
    & $add '<p class="muted"><b>Verificaci&#243;n</b>: MATCH = id&#233;ntico al hash de copia; VOLATIL = fichero en uso durante la adquisici&#243;n (se registran ambos hashes, no es alteraci&#243;n); RESELLADO = producto generado por el propio script actualizado tras su primer hash (se registra el hash final); MISMATCH = divergencia real a investigar.</p>'
    & $add (New-ReportTable -Rows $evOrdered -Columns $colEv -MaxRows 500 -SourceCsv '..\..\04_Hashes\hash_manifest.csv')
    & $add '<div class="callout"><p>Manifiesto completo y sello del conjunto en <span class="mono">04_Hashes\hash_manifest.csv</span> y <span class="mono">manifest_seal.csv</span>. Para fecha cierta, firmar o sellar con TSA (eIDAS).</p></div>'
    & $add '</section>'

    
    & $add '<section id="secM"><h2><span class="sn">&#167;M</span>Cadena de custodia (comandos ejecutados)</h2>'
    & $add ('<p class="lead">Se registraron <b>' + $script:CommandLog.Count + '</b> comandos con su c&#243;digo de salida, garantizando la reproducibilidad. Listado completo en <span class="mono">01_Acquisition_Logs\commands_' + (ConvertTo-HtmlSafe $script:AcquisitionId) + '.csv</span>.</p>')
    $failedCmds = @($script:CommandLog | Where-Object { -not $_.Success })
    & $add '<h3>Comandos sin ejecuci&#243;n correcta (herramienta ausente o error)</h3>'
    $colCmd = @(@{P='TimestampUTC';L='Fecha UTC';Mono=$true},@{P='Command';L='Comando';Mono=$true;Max=90},@{P='ExitCode';L='Salida';Mono=$true},@{P='Description';L='Descripci&#243;n';Max=60})
    & $add (New-ReportTable -Rows $failedCmds -Columns $colCmd -MaxRows 200 -EmptyText 'Todos los comandos se ejecutaron correctamente.')
    & $add '</section>'

    
    & $add '<section id="secN"><h2><span class="sn">&#167;N</span>Disponibilidad de artefactos y evidencias no obtenidas</h2>'
    & $add '<p class="lead">Relaci&#243;n transparente de lo que no pudo obtenerse, clasificado por <b>estado</b>. Es esencial distinguir un artefacto que <b>leg&#237;timamente no existe</b> en este sistema (no es un fallo) de un <b>fallo real de adquisici&#243;n</b> (acceso denegado, bloqueo) o de lo que <b>requiere otra fuente</b> (imagen offline, controlador de dominio). La ausencia de un registro no equivale a la ausencia del hecho.</p>'
    $benignStates = @('NOT_INSTALLED','NOT_APPLICABLE','EMPTY','DISABLED','NOT_FOUND')
    $externalStates = @('REQUIRES_OFFLINE_ACQUISITION','REQUIRES_EXTERNAL_SOURCE')
    $failStates = @('ACCESS_DENIED','LOCKED','ACQUISITION_FAILED','PARSE_FAILED','UNAVAILABLE')
    $miss = @($script:MissingEvidence)
    $byStatus = @{}
    foreach ($m in $miss) { $st = $(if ($m.Status) { $m.Status } else { 'UNAVAILABLE' }); if (-not $byStatus.ContainsKey($st)) { $byStatus[$st] = 0 }; $byStatus[$st]++ }
    if ($byStatus.Count -gt 0) {
        $sumRows = @($byStatus.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object {
            New-Object PSObject -Property @{ Estado = $_.Key; Etiqueta = (Get-ArtifactStatusLabel -Status $_.Key); Cantidad = $_.Value }
        })
        & $add '<h3>Resumen por estado</h3>'
        & $add (New-ReportTable -Rows $sumRows -Columns @(@{P='Etiqueta';L='Estado';Max=44},@{P='Estado';L='Codigo';Mono=$true},@{P='Cantidad';L='Cantidad';Mono=$true}) -MaxRows 40 -EmptyText 'Sin registros.')
    }
    $colMiss = @(@{P='StatusLabel';L='Estado';Max=30},@{P='Evidence';L='Artefacto / evidencia';Max=58},@{P='Reason';L='Detalle';Max=80})
    $benign = @($miss | Where-Object { $benignStates -contains $_.Status })
    & $add '<h3>1) Ausencias leg&#237;timas (no constituyen fallo de adquisici&#243;n)</h3>'
    & $add '<p class="muted">Artefactos que no existen, no aplican a esta edici&#243;n de Windows, o existen pero sin registros. Su ausencia es un dato del sistema, no un error del perito.</p>'
    & $add (New-ReportTable -Rows $benign -Columns $colMiss -MaxRows 300 -EmptyText 'No hay artefactos en esta categoria.')
    $external = @($miss | Where-Object { $externalStates -contains $_.Status })
    & $add '<h3>2) Requieren imagen offline o fuente externa</h3>'
    & $add '<p class="muted">Evidencia que existe pero no puede obtenerse en vivo: precisa imagen forense de disco, instant&#225;nea VSS analizada en fr&#237;o, o una fuente fuera del equipo (controlador de dominio, firewall/VPN).</p>'
    & $add (New-ReportTable -Rows $external -Columns $colMiss -MaxRows 200 -EmptyText 'No hay artefactos en esta categoria.')
    $fails = @($miss | Where-Object { $failStates -contains $_.Status -or -not $_.Status })
    & $add '<h3>3) Fallos reales de adquisici&#243;n</h3>'
    & $add '<p class="muted">Casos en que el artefacto deber&#237;a haberse obtenido pero no se logr&#243;: acceso denegado (relanzar como administrador), fichero bloqueado, o error de adquisici&#243;n/interpretaci&#243;n. Son los &#250;nicos que requieren acci&#243;n del perito.</p>'
    & $add (New-ReportTable -Rows $fails -Columns $colMiss -MaxRows 200 -EmptyText 'No se registraron fallos reales de adquisicion.')
    & $add '</section>'

    
    & $add '<section id="secU"><h2><span class="sn">&#167;U</span>Eventos hist&#243;ricos recuperados (VSS / archivados)</h2>'
    & $add '<p class="lead">El registro Security en vivo tiene retenci&#243;n limitada y <b>rota</b>: los eventos anteriores se sobrescriben. Aqu&#237; se muestran los inicios de sesi&#243;n y cambios de cuenta <b>recuperados de instant&#225;neas VSS y de los .evtx archivados</b>, que <b>amplian la ventana temporal</b> mas alla de lo que conserva el log actual. Son los que permiten ver, p.ej., los accesos de la noche de los hechos aunque ya no est&#233;n en el log vivo.</p>'
    $colHist = @(
        @{P='TimestampUTC';L='Fecha UTC';Mono=$true},
        @{P='TimestampLocal';L='Hora local';Mono=$true},
        @{P='EventId';L='ID';Mono=$true},
        @{P='User';L='Usuario'},
        @{P='SourceIP';L='IP origen';Mono=$true},
        @{P='WorkstationName';L='Estacion';Max=20},
        @{P='LogonType';L='Tipo';Mono=$true},
        @{P='OrigenHistorico';L='Recuperado de';Max=30}
    )
    & $add (New-ReportTable -Rows (Get-ReportCsv '20b_security_events_historical').Rows -Columns $colHist -MaxRows 500 -SourceCsv '20b_security_events_historical.csv' -EmptyText 'No se recuperaron eventos hist&#243;ricos adicionales (sin instant&#225;neas VSS utiles ni .evtx archivados, o su cobertura ya estaba en el log vivo).')
    & $add '<div class="callout"><p><b>C&#243;mo interpretarlo:</b> estos eventos NO estaban en el registro en vivo (ya rotado); se han recuperado de copias anteriores del propio equipo (instant&#225;neas de volumen y logs archivados). Su valor probatorio es el mismo que el de un evento vivo: son registros originales de Windows con su fecha. La columna <b>Recuperado de</b> indica la instant&#225;nea o archivo de procedencia. Los .evtx originales quedan preservados en <span class="mono">02_Raw_Evidence\\EventLogs\\Historical</span> con su hash.</p></div>'
    & $add '</section>'

    
    & $add '<section id="secZ"><h2><span class="sn">&#167;Z</span>Anexo general de c&#243;digos de evento (glosario)</h2>'
    & $add '<p class="lead">Glosario de todos los identificadores de evento y c&#243;digos citados en el informe, para su consulta e interpretaci&#243;n. Los c&#243;digos son est&#225;ndar de Windows e independientes del idioma del sistema.</p>'
    & $add '<div class="anexo"><h4>Inicio y cierre de sesi&#243;n (Security)</h4><table><tr><th>ID</th><th>Significado</th></tr>'
    & $add '<tr><td>4624</td><td>Inicio de sesion correcto</td></tr>'
    & $add '<tr><td>4625</td><td>Intento de inicio de sesion fallido</td></tr>'
    & $add '<tr><td>4634 / 4647</td><td>Cierre de sesion</td></tr>'
    & $add '<tr><td>4648</td><td>Inicio con credenciales explicitas (RunAs / iniciar como otro usuario)</td></tr>'
    & $add '<tr><td>4672</td><td>Se asignaron privilegios especiales (sesion con permisos de administrador)</td></tr></table></div>'
    & $add '<div class="anexo"><h4>Gesti&#243;n de cuentas y grupos (Security)</h4><table><tr><th>ID</th><th>Significado</th></tr>'
    & $add '<tr><td>4720</td><td>Cuenta de usuario CREADA</td></tr><tr><td>4722</td><td>Cuenta habilitada</td></tr>'
    & $add '<tr><td>4725</td><td>Cuenta deshabilitada</td></tr><tr><td>4726</td><td>Cuenta ELIMINADA</td></tr>'
    & $add '<tr><td>4738</td><td>Cuenta modificada</td></tr><tr><td>4740</td><td>Cuenta bloqueada</td></tr>'
    & $add '<tr><td>4767</td><td>Cuenta desbloqueada</td></tr><tr><td>4781</td><td>Cuenta renombrada</td></tr>'
    & $add '<tr><td>4723</td><td>Cambio de contrasena (por el propio usuario)</td></tr>'
    & $add '<tr><td>4724</td><td>Restablecimiento de contrasena (por un administrador u otra cuenta)</td></tr>'
    & $add '<tr><td>4728 / 4732 / 4756</td><td>Miembro ANADIDO a grupo (global / local / universal)</td></tr>'
    & $add '<tr><td>4729 / 4733 / 4757</td><td>Miembro ELIMINADO de grupo</td></tr></table></div>'
    & $add '<div class="anexo"><h4>Escritorio remoto RDP (Terminal Services)</h4><table><tr><th>ID</th><th>Significado</th></tr>'
    & $add '<tr><td>1149</td><td>Autenticacion RDP correcta (usuario e IP de origen)</td></tr>'
    & $add '<tr><td>21</td><td>Inicio de sesion de la sesion RDP</td></tr><tr><td>22</td><td>Carga del escritorio/shell</td></tr>'
    & $add '<tr><td>24</td><td>Desconexion (deja la sesion abierta)</td></tr><tr><td>25</td><td>Reconexion a sesion desconectada</td></tr>'
    & $add '<tr><td>23</td><td>Cierre de sesion completo</td></tr>'
    & $add '<tr><td>39</td><td>La sesion fue desconectada por otra sesion</td></tr><tr><td>40</td><td>Sesion desconectada (con motivo)</td></tr></table></div>'
    & $add '<div class="anexo"><h4>Ejecuci&#243;n de procesos y comandos</h4><table><tr><th>ID</th><th>Significado</th></tr>'
    & $add '<tr><td>4688</td><td>Creacion de un nuevo proceso (con linea de comandos si la auditoria lo incluye)</td></tr>'
    & $add '<tr><td>4104</td><td>PowerShell: bloque de script ejecutado (Script Block Logging)</td></tr>'
    & $add '<tr><td>4103</td><td>PowerShell: registro de canalizacion/modulos</td></tr></table></div>'
    & $add '<div class="anexo"><h4>Acceso a objetos y borrado</h4><table><tr><th>ID</th><th>Significado</th></tr>'
    & $add '<tr><td>4660</td><td>Un objeto fue ELIMINADO</td></tr>'
    & $add '<tr><td>4663</td><td>Intento de acceso a un objeto (lectura/escritura/borrado)</td></tr>'
    & $add '<tr><td>5140 / 5145</td><td>Acceso a un recurso compartido de red (SMB)</td></tr>'
    & $add '<tr><td>5142 / 5143 / 5144</td><td>Recurso compartido creado / modificado / eliminado</td></tr></table></div>'
    & $add '<div class="anexo"><h4>Antiforensia (borrado de registros)</h4><table><tr><th>ID</th><th>Significado</th></tr>'
    & $add '<tr><td>1102</td><td>Se borro el registro de SEGURIDAD (indicio de antiforensia)</td></tr>'
    & $add '<tr><td>104</td><td>Se borro un registro de eventos</td></tr></table></div>'
    & $add '<div class="anexo"><h4>Tipos de inicio de sesion (Logon Type)</h4><table><tr><th>Tipo</th><th>Significado</th></tr>'
    & $add '<tr><td>2</td><td>Interactivo (teclado del propio equipo)</td></tr><tr><td>3</td><td>Red (carpeta/impresora compartida, SMB)</td></tr>'
    & $add '<tr><td>4</td><td>Lote (tarea programada)</td></tr><tr><td>5</td><td>Servicio</td></tr>'
    & $add '<tr><td>7</td><td>Desbloqueo de estacion</td></tr><tr><td>8</td><td>Red con credenciales en claro</td></tr>'
    & $add '<tr><td>9</td><td>Credenciales nuevas (RunAs /netonly)</td></tr>'
    & $add '<tr><td>10</td><td>Escritorio remoto (RDP / Terminal Services)</td></tr>'
    & $add '<tr><td>11</td><td>Interactivo con credenciales en cache</td></tr></table></div>'
    & $add '</section>'

    
    & $add '<div class="footer">Informe generado autom&#225;ticamente por <span class="mono">Invoke-ForensicTriage.ps1</span> durante la adquisici&#243;n. No sustituye el an&#225;lisis pericial: las conclusiones exigen correlaci&#243;n y validaci&#243;n conforme a UNE&nbsp;71506. '
    & $add ('Adquisici&#243;n <span class="mono">' + (ConvertTo-HtmlSafe $script:AcquisitionId) + '</span> &#183; generado ' + (ConvertTo-HtmlSafe $nowUtc) + ' UTC.</div>')
    & $add '</div></body></html>'

    
    $out = Join-Path $script:Paths.Report ('Informe_Pericial_{0}.html' -f $script:AcquisitionId)
    try {
        [System.IO.File]::WriteAllText($out, $H.ToString(), (New-Object System.Text.UTF8Encoding($false)))
        $rHash = Get-EvidenceFileHash -Path $out -Algorithm SHA256
        ('{0}  {1}' -f $rHash, (Split-Path $out -Leaf)) | Out-File -LiteralPath ($out + '.sha256.txt') -Encoding ASCII
        Write-ForensicLog -Message ('Informe pericial HTML generado: {0} (SHA256={1})' -f $out, $rHash)
        
        $copy = Join-Path $script:Paths.ParsedHTML 'Informe_Pericial.html'
        try { [System.IO.File]::WriteAllText($copy, $H.ToString(), (New-Object System.Text.UTF8Encoding($false))) } catch { }
    } catch {
        Write-ForensicLog -Level ERROR -Message ('No se pudo escribir el informe HTML: {0}' -f $_.Exception.Message)
    }
}

function Export-ToolInformation {
    
    $tools = 'wevtutil.exe','auditpol.exe','reg.exe','sc.exe','schtasks.exe','netsh.exe','certutil.exe','esentutl.exe','vssadmin.exe','fsutil.exe','w32tm.exe','systeminfo.exe'
    $info = New-Object System.Collections.ArrayList
    foreach ($t in $tools) {
        $cmd = Get-Command $t -ErrorAction SilentlyContinue
        $ver = $null; $path = $null; $hash = $null
        if ($cmd) {
            $path = $cmd.Source
            if (-not $path) { $path = $cmd.Definition }
            if ($path -and (Test-Path -LiteralPath $path)) {
                try { $ver = (Get-Item -LiteralPath $path).VersionInfo.FileVersion } catch { }
                $hash = Get-EvidenceFileHash -Path $path -Algorithm SHA256
            }
        }
        [void]$info.Add((New-Object PSObject -Property @{
            Tool = $t; Available = [bool]$cmd; Path = $path; FileVersion = $ver; SHA256 = $hash
        }))
    }
    $out = Join-Path $script:Paths.ToolInfo 'native_tools.csv'
    $info | Export-Csv -LiteralPath $out -NoTypeInformation -Encoding UTF8
    Register-Evidence -Path $out -Category 'ToolInfo' -SourceDescription 'Inventario de herramientas nativas empleadas'
}

function Export-CaseIntegritySeal {
    







    Write-ForensicLog -Message '--- Sellado de integridad del caso (hash raiz + cadena de custodia) ---'
    $hashesDir = $script:Paths.Hashes
    $fullCsv = Join-Path $hashesDir 'case_manifest_full.csv'
    $rootTxt = Join-Path $hashesDir 'ROOT_HASH.txt'
    
    
    $logLeaf = $null; try { $logLeaf = Split-Path $script:LogFile -Leaf } catch { }
    $exclude = @('case_manifest_full.csv', 'ROOT_HASH.txt', 'acquisition_summary.json', 'command_log.csv', 'error_log.csv', 'acquisition_command_log.csv')
    if ($logLeaf) { $exclude += $logLeaf }

    $records = New-Object System.Collections.ArrayList
    $lines = New-Object System.Collections.ArrayList
    $files = @()
    try { $files = @(Get-ChildItem -LiteralPath $script:CaseRoot -Recurse -File -Force -ErrorAction SilentlyContinue) } catch { }
    foreach ($f in ($files | Sort-Object FullName)) {
        $rel = $f.FullName.Substring($script:CaseRoot.Length).TrimStart('\', '/')
        if ($exclude -contains $f.Name) { continue }
        if ($rel -like '01_Acquisition_Logs*') { continue }
        if ($f.Name -like 'verificacion_*') { continue }
        if ($f.Name -eq 'process_files_seal.csv') { continue }
        $h = Get-EvidenceFileHash -Path $f.FullName -Algorithm SHA256
        [void]$records.Add((New-Object PSObject -Property @{
            RelativePath = $rel; SizeBytes = $f.Length
            ModifiedUTC = $f.LastWriteTimeUtc.ToString($script:TsFmt); SHA256 = $h
        }))
        $hl = $(if ($h) { $h.ToLowerInvariant() } else { $h }); [void]$lines.Add(('{0}  {1}' -f $hl, ($rel -replace '\\', '/')))
    }
    $records | Export-Csv -LiteralPath $fullCsv -NoTypeInformation -Encoding UTF8

    
    $joined = (($lines | Sort-Object) -join "`n")
    $rootHash = $null
    try {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($joined)
        $rootHash = -join ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') })
    } catch { }

    $sysTimeUtc = (Get-Date).ToUniversalTime()
    $rootContent = @()
    $rootContent += 'SELLADO DE INTEGRIDAD DEL CASO (HASH RAIZ)'
    $rootContent += '========================================='
    $rootContent += ('Caso                 : {0}' -f $script:CaseId)
    $rootContent += ('Adquisicion          : {0}' -f $script:AcquisitionId)
    $rootContent += ('Equipo               : {0}' -f $script:TargetComputer)
    $rootContent += ('Ficheros sellados    : {0}' -f $records.Count)
    $rootContent += ('Algoritmo            : SHA-256 (arbol de hashes; hash del listado ordenado hash+ruta)')
    $rootContent += ('HASH RAIZ            : {0}' -f $rootHash)
    $rootContent += ('Huella del script    : {0}' -f $script:SelfHash)
    $rootContent += ('Sellado (reloj sist.): {0} UTC' -f $sysTimeUtc.ToString($script:TsFmt))
    $rootContent += ''
    $rootContent += 'Verificacion independiente: ejecute Verify-ForensicEvidence.ps1 sobre esta carpeta.'
    $rootContent += 'Cualquier alteracion posterior de un solo byte modificara el HASH RAIZ.'
    [System.IO.File]::WriteAllLines($rootTxt, [string[]]$rootContent, (New-Object System.Text.UTF8Encoding($false)))

    
    
    $procSeal = New-Object System.Collections.ArrayList
    $procFiles = @()
    try { $procFiles += @(Get-ChildItem -LiteralPath $script:Paths.AcqLogs -File -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName }) } catch { }
    $procFiles += (Join-Path $script:Paths.Meta 'acquisition_summary.json')
    $procFiles += (Join-Path $script:Paths.Meta 'cadena_de_custodia.txt')
    foreach ($pf in $procFiles) {
        if ($pf -and (Test-Path -LiteralPath $pf)) {
            [void]$procSeal.Add((New-Object PSObject -Property @{ Fichero=(Split-Path $pf -Leaf); SHA256=(Get-EvidenceFileHash -Path $pf -Algorithm SHA256); SelladoUTC=(Get-Date).ToUniversalTime().ToString($script:TsFmt) }))
        }
    }
    if ($procSeal.Count -gt 0) { $procSeal | Export-Csv -LiteralPath (Join-Path $hashesDir 'process_files_seal.csv') -NoTypeInformation -Encoding UTF8 }

    $tsaNote = 'No aplicado en vivo. Para fecha cierta oponible a terceros, sellar ROOT_HASH.txt con una Autoridad de Sellado de Tiempo (TSA RFC-3161 / eIDAS) o firmarlo con el certificado del perito.'

    $custodia = @()
    $custodia += 'DOCUMENTO DE CADENA DE CUSTODIA'
    $custodia += '==============================='
    $custodia += ''
    $custodia += ('Caso                 : {0}' -f $script:CaseId)
    $custodia += ('Identificador adq.   : {0}' -f $script:AcquisitionId)
    $custodia += ('Perito / examinador  : {0}' -f $Examiner)
    $custodia += ('Organizacion         : {0}' -f $Organization)
    $custodia += ('Equipo analizado     : {0}' -f $script:TargetComputer)
    $custodia += ('Usuario ejecutor     : {0}' -f ('{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME))
    $custodia += ('Elevacion (admin)    : {0}' -f $script:IsAdmin)
    $custodia += ('Herramienta          : Invoke-ForensicTriage.ps1')
    $custodia += ('Huella SHA-256 script: {0}' -f $script:SelfHash)
    $custodia += ('PowerShell / SO      : {0} / {1}' -f $PSVersionTable.PSVersion, [System.Environment]::OSVersion.VersionString)
    $custodia += ('Inicio adquisicion   : {0} UTC' -f $script:StartUtc.ToString($script:TsFmt))
    $custodia += ('Fin (sellado)        : {0} UTC' -f $sysTimeUtc.ToString($script:TsFmt))
    $custodia += ('Metodo               : adquisicion en vivo, solo lectura (no destructiva). Referencias UNE 71505/71506 y RFC 3227.')
    $custodia += ('Ficheros de evidencia: {0}' -f $records.Count)
    $custodia += ('HASH RAIZ del conjunto: {0}' -f $rootHash)
    $custodia += ('Sellado de tiempo    : {0}' -f $tsaNote)
    $custodia += ''
    $custodia += 'DECLARACION'
    $custodia += '-----------'
    $custodia += 'La evidencia relacionada en case_manifest_full.csv fue adquirida por el perito'
    $custodia += 'arriba indicado mediante la herramienta y version resenadas, en modo de solo'
    $custodia += 'lectura. Cada fichero consta con su hash SHA-256 individual y el conjunto queda'
    $custodia += 'sellado por el HASH RAIZ. La integridad puede comprobarla cualquier tercero'
    $custodia += 'ejecutando el verificador independiente Verify-ForensicEvidence.ps1.'
    $custodia += ''
    $custodia += 'REGISTRO DE TRANSFERENCIAS (a cumplimentar manualmente)'
    $custodia += '------------------------------------------------------'
    $custodia += 'Fecha/hora        Entrega (nombre/firma)      Recibe (nombre/firma)      Motivo'
    $custodia += '................  ..........................  .........................  ............'
    $custodia += '................  ..........................  .........................  ............'
    $custFile = Join-Path $script:Paths.Meta 'cadena_de_custodia.txt'
    [System.IO.File]::WriteAllLines($custFile, [string[]]$custodia, (New-Object System.Text.UTF8Encoding($true)))

    Write-ForensicLog -Message ('Sellado completo: {0} ficheros, HASH RAIZ={1}' -f $records.Count, $rootHash)
    Write-ForensicLog -Message ('Cadena de custodia: {0}' -f $custFile)
}

function Complete-Acquisition {
    Build-GlobalTimeline
    Export-UnifiedTimeline
    Export-ToolInformation
    Export-CommandAndErrorLogs
    Export-HashManifestAndVerify
    Export-HtmlSummary
    
    Export-CommandAndErrorLogs

    $endLocal = Get-Date
    $summary = New-Object PSObject -Property @{
        AcquisitionId       = $script:AcquisitionId
        StartUTC            = $script:StartUtc.ToString($script:TsFmt)
        EndUTC              = $endLocal.ToUniversalTime().ToString($script:TsFmt)
        DurationMinutes     = [math]::Round(($endLocal - $script:StartLocal).TotalMinutes, 2)
        EvidenceCount       = $script:EvidenceList.Count
        MissingEvidenceCount= $script:MissingEvidence.Count
        ErrorCount          = $script:ErrorLog.Count
        WarningCount        = $script:WarningLog.Count
        SourcesQueried      = ($script:SourcesQueried -join ' | ')
    }
    $sumFile = Join-Path $script:Paths.Meta 'acquisition_summary.json'
    try {
        [System.IO.File]::WriteAllText($sumFile, ($summary | ConvertTo-Json -Depth 3), (New-Object System.Text.UTF8Encoding($false)))
    } catch { }

    if ($CompressOutput) {
        if (Test-CommandAvailable 'Compress-Archive') {
            $zip = Join-Path $script:OutputPath ($script:CaseId + '_' + $script:AcquisitionId + '.zip')
            try {
                Compress-Archive -Path $script:CaseRoot -DestinationPath $zip -Force -ErrorAction Stop
                $zipHash = Get-EvidenceFileHash -Path $zip -Algorithm SHA256
                Write-ForensicLog -Message ('Paquete comprimido: {0} SHA256={1}' -f $zip, $zipHash)
                ('{0}  {1}' -f $zipHash, $zip) | Out-File -LiteralPath ($zip + '.sha256.txt') -Encoding ASCII
            } catch {
                Write-ForensicLog -Level ERROR -Message ('Compresion fallida: {0}' -f $_.Exception.Message)
            }
        } else {
            Write-ForensicLog -Level WARN -Message 'Compress-Archive no disponible (PS<5): se omite la compresion, sin usar herramientas externas.'
        }
    }

    Write-ForensicLog -Message ('=== FIN ADQUISICION === Evidencias: {0} | No disponibles: {1} | Errores: {2} | Duracion: {3} min' -f `
        $script:EvidenceList.Count, $script:MissingEvidence.Count, $script:ErrorLog.Count, $summary.DurationMinutes)

    
    
    
    Export-CommandAndErrorLogs
    Remove-CaseSnapshot
    Export-CaseIntegritySeal
    Write-Host ''
    Write-Host '================ RESUMEN FINAL ================' -ForegroundColor Green
    Write-Host ('  Evidencias adquiridas  : {0}' -f $script:EvidenceList.Count)
    Write-Host ('  No disponibles (causa) : {0}  -> 07_Errors\missing_evidence.csv' -f $script:MissingEvidence.Count)
    Write-Host ('  Errores / advertencias : {0} / {1}' -f $script:ErrorLog.Count, $script:WarningLog.Count)
    Write-Host ('  Manifiesto de hashes   : 04_Hashes\hash_manifest.csv (+ sello)' )
    Write-Host ('  Ruta del caso          : {0}' -f $script:CaseRoot)
    Write-Host '==============================================='  -ForegroundColor Green

    if (Test-CommandAvailable 'Stop-Transcript') {
        try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
    }
}




$exitCode = 0
try {
    if ($EndDate -le $StartDate) {
        throw 'EndDate debe ser posterior a StartDate.'
    }
    Initialize-Environment

    
    $moduleList = @(
        'Invoke-ModuleSystemInfo','Invoke-ModuleUsers','Invoke-ModuleEventLogs',
        'Invoke-ModuleRegistry','Invoke-ModuleFileSystem','Invoke-ModuleRemoteAccess',
        'Invoke-ModuleNetwork','Invoke-ModuleLogonCorrelation','Invoke-ModuleHistoricalLogs','Invoke-ModuleVolatile','Invoke-ModulePersistence','Invoke-ModuleEvidencePreservation',
        'Invoke-ModuleDeletedFiles','Invoke-ModuleUserActivity','Invoke-ModuleProgramExecution','Invoke-ModuleUSBDevices','Invoke-ModuleBrowserActivity','Invoke-ModulePasswordActivity','Invoke-ModuleSecurityTools','Invoke-ModuleAITools'
    )
    foreach ($mod in $moduleList) {
        Set-HeartbeatModule -Name ($mod -replace '^Invoke-Module','')
        [void](Disable-QuickEditMode)   
        $modT0 = Get-Date
        try {
            & $mod
            Write-ForensicLog -Level DEBUG -Message ('Modulo {0}: {1} s' -f $mod, [int]((Get-Date) - $modT0).TotalSeconds)
        } catch {
            Write-ForensicLog -Level ERROR -Message ('Modulo {0} interrumpido por excepcion no controlada: {1}. Se continua con el resto.' -f $mod, $_.Exception.Message)
            Register-MissingEvidence -Evidence $mod -Reason ('Excepcion no controlada: {0}' -f $_.Exception.Message)
        }
    }

    Complete-Acquisition
} catch {
    $exitCode = 1
    $msg = ('ERROR FATAL: {0}' -f $_.Exception.Message)
    if ($script:LogFile) { Write-ForensicLog -Level ERROR -Message $msg } else { Write-Host $msg -ForegroundColor Red }
    try { Complete-Acquisition } catch { }
} finally {
    Stop-HashPool
    Stop-Heartbeat
    exit $exitCode
}
