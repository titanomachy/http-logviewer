# Run in the current PowerShell session to check its aliases and functions.
param(
    [string]$Executable = '',
    [string]$BinDirectory = $(if ($env:NIMBLE_DIR) { Join-Path $env:NIMBLE_DIR 'bin' } else { Join-Path $HOME '.nimble/bin' })
)

$ErrorActionPreference = 'Stop'
if (!$Executable) {
    $installed = Get-Command http_logviewer -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($installed) { $Executable = $installed.Source }
    elseif (Test-Path './build/http_logviewer.exe' -PathType Leaf) { $Executable = './build/http_logviewer.exe' }
}
if (!$Executable -or !(Test-Path -LiteralPath $Executable -PathType Leaf)) {
    throw 'Build or install http_logviewer first, or pass its executable path.'
}
$Executable = (Resolve-Path -LiteralPath $Executable).Path
New-Item -ItemType Directory -Path $BinDirectory -Force | Out-Null
$BinDirectory = (Resolve-Path -LiteralPath $BinDirectory).Path
$name = 'hlv'

while ($true) {
    $conflict = $false
    if ($name -notmatch '^[a-zA-Z0-9_][a-zA-Z0-9_-]*$') {
        Write-Host 'Use a command name containing only letters, digits, underscores, or hyphens.'
        $conflict = $true
    } else {
        $destination = Join-Path $BinDirectory "$name.cmd"
        # A .cmd launcher works in PowerShell and cmd.exe without requiring
        # permission to create Windows symlinks or changing execution policy.
        $escapedExecutable = $Executable.Replace('%', '%%')
        $launcher = "@echo off`r`nsetlocal DisableDelayedExpansion`r`n`"$escapedExecutable`" %*`r`n"
        $destinationItem = Get-Item -LiteralPath $destination -Force -ErrorAction SilentlyContinue
        $existingLauncher = $destinationItem -and (Test-Path -LiteralPath $destination -PathType Leaf) -and
            ([IO.File]::ReadAllText($destination) -ceq $launcher)
        foreach ($command in @(Get-Command $name -All -ErrorAction SilentlyContinue)) {
            if ($existingLauncher -and $command.CommandType -eq 'Application' -and $command.Source -eq $destination) { continue }
            Write-Host "Conflict: $($command.CommandType) $($command.Name): $($command.Definition)"
            $conflict = $true
        }
        if ($destinationItem -and !$existingLauncher) {
            Write-Host "Conflict: destination already exists: $destination"
            $conflict = $true
        }
    }
    if (!$conflict) {
        if ($existingLauncher) { Write-Host "Shortcut already installed: $destination" }
        else {
            # CreateNew refuses to overwrite a file even if another process
            # creates it after the collision check.
            $stream = [IO.File]::Open($destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
            try {
                $bytes = [Text.Encoding]::Default.GetBytes($launcher)
                $stream.Write($bytes, 0, $bytes.Length)
            } finally { $stream.Dispose() }
            Write-Host "Installed $destination -> $Executable"
        }
        if ($BinDirectory -notin ($env:PATH -split ';')) { Write-Host "Add $BinDirectory to PATH to use $name." }
        break
    }
    $name = Read-Host 'Enter a different shortcut name, or press Enter to skip'
    if (!$name) {
        Write-Host 'Skipped shortcut installation; existing commands and configuration are unchanged.'
        break
    }
}
