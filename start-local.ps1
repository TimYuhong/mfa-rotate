$ErrorActionPreference = 'Stop'
$projectPath = $PSScriptRoot
$settingsPath = Join-Path $projectPath '.env'
$pythonPath = Join-Path $projectPath '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $settingsPath) -or -not (Test-Path -LiteralPath $pythonPath)) {
    throw 'Missing local settings or project Python runtime.'
}

$settings = @{}
foreach ($settingsLine in Get-Content -LiteralPath $settingsPath) {
    if ([string]::IsNullOrWhiteSpace($settingsLine) -or $settingsLine.TrimStart().StartsWith('#')) { continue }
    if ($settingsLine -notmatch '^(MFA_MODE|MFA_LOCAL_DEV|MFA_ORIGIN|MFA_ACCESS_KEY|MFA_MAX_CONCURRENT)=(.*)$') {
        throw 'Unsupported local setting.'
    }
    $settings[$Matches[1]] = $Matches[2]
}
foreach ($settingsName in @('MFA_MODE','MFA_LOCAL_DEV','MFA_ORIGIN','MFA_ACCESS_KEY')) {
    if (-not $settings.ContainsKey($settingsName) -or [string]::IsNullOrEmpty($settings[$settingsName])) {
        throw "Missing local setting: $settingsName"
    }
    [Environment]::SetEnvironmentVariable($settingsName, $settings[$settingsName], 'Process')
}
if ($settings.ContainsKey('MFA_MAX_CONCURRENT')) {
    [Environment]::SetEnvironmentVariable('MFA_MAX_CONCURRENT', $settings['MFA_MAX_CONCURRENT'], 'Process')
}
$env:PYTHONDONTWRITEBYTECODE = '1'
Push-Location -LiteralPath $projectPath
try {
    & $pythonPath -B -m uvicorn app.server:app --host 127.0.0.1 --port 8790 --no-access-log --log-level warning
    if ($LASTEXITCODE -ne 0) { throw 'Local service exited with an error.' }
} finally {
    Pop-Location
}
