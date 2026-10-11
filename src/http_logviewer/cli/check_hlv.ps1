# Nimble pre-install check; run in PowerShell to include its aliases/functions.
$ErrorActionPreference = 'Stop'
$nimbleDirectory = if ($env:NIMBLE_DIR) { $env:NIMBLE_DIR } else { Join-Path $HOME '.nimble' }
$binDirectory = Join-Path $nimbleDirectory 'bin'
$conflict = $false

function Test-ViewerLauncher([string]$Path) {
    if (!(Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    # Nimble's Windows .cmd launcher points into the owning package directory.
    $extension = [IO.Path]::GetExtension($Path)
    if ($extension -and $extension -ne '.cmd') { return $false }
    if ((Get-Item -LiteralPath $Path).Length -gt 16384) { return $false }
    $contents = [IO.File]::ReadAllText($Path)
    if ($extension -eq '.cmd') {
        return $contents -match '(?m)^@?"(?:%~dp0[\\/]|[^"\r\n]+[\\/])(?:\.\.[\\/])?pkgs2?[\\/]http_logviewer-[^"\r\n]+[\\/](?:hlv|http_logviewer)\.exe" %\*\s*$'
    }
    if (!$extension) {
        # Nimble also installs a Git Bash stub alongside its .cmd launcher.
        return $contents -match '^"[^\r\n]+[\\/]pkgs2?[\\/]http_logviewer-[^"\r\n]+[\\/](?:hlv|http_logviewer)\.exe" "\$@"\s*$'
    }
    return $false
}

foreach ($command in @(Get-Command hlv -All -ErrorAction SilentlyContinue)) {
    if ($command.CommandType -eq 'Application' -and (Test-ViewerLauncher $command.Source)) { continue }
    Write-Host "Conflict: $($command.CommandType) $($command.Name): $($command.Definition)"
    $conflict = $true
}
foreach ($name in @('hlv', 'hlv.cmd', 'hlv.exe', 'hlv.ps1', 'hlv.bat')) {
    $destination = Join-Path $binDirectory $name
    $item = Get-Item -LiteralPath $destination -Force -ErrorAction SilentlyContinue
    if ($item -and !(Test-ViewerLauncher $destination)) {
        Write-Host "Conflict: destination already exists: $destination"
        $conflict = $true
    }
}
if ($conflict) {
    Write-Host "Nimble will install hlv in $binDirectory, replacing its launchers if present."
    Write-Host 'Other PATH commands may be shadowed; aliases and functions remain unchanged.'
    $answer = Read-Host 'Continue installing both commands? [y/N]'
    if ($answer -notmatch '^(?i:y|yes)$') {
        throw 'Installation cancelled; resolve the hlv conflict and retry.'
    }
}
