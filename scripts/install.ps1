param(
  [ValidateSet("codex", "claude", "both")]
  [string]$Target = "both",
  [string]$CodexHome = "$env:USERPROFILE\.codex",
  [string]$ClaudeHome = "$env:USERPROFILE\.claude"
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

function Install-SkillSet {
  param(
    [Parameter(Mandatory = $true)][string]$SourceRoot,
    [Parameter(Mandatory = $true)][string]$DestinationHome,
    [Parameter(Mandatory = $true)][string]$Label
  )

  $sourceSkills = Join-Path $SourceRoot "skills"
  $destinationSkills = Join-Path $DestinationHome "skills"
  $backupRoot = Join-Path $DestinationHome "backups\firmware-skills-$timestamp"

  if (-not (Test-Path $sourceSkills)) {
    throw "Missing source skill directory: $sourceSkills"
  }

  New-Item -ItemType Directory -Path $destinationSkills -Force | Out-Null
  New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null

  Get-ChildItem -Path $sourceSkills -Directory -Filter "firmware-*" | ForEach-Object {
    $destination = Join-Path $destinationSkills $_.Name
    if (Test-Path $destination) {
      Copy-Item -LiteralPath $destination -Destination $backupRoot -Recurse -Force
    }
    Copy-Item -LiteralPath $_.FullName -Destination $destinationSkills -Recurse -Force
  }

  Write-Host "$Label skills installed to $destinationSkills"
  Write-Host "$Label backup written to $backupRoot"
}

if ($Target -eq "codex" -or $Target -eq "both") {
  Install-SkillSet -SourceRoot (Join-Path $repoRoot "codex") -DestinationHome $CodexHome -Label "Codex"
}

if ($Target -eq "claude" -or $Target -eq "both") {
  Install-SkillSet -SourceRoot (Join-Path $repoRoot "claude") -DestinationHome $ClaudeHome -Label "Claude"
}

