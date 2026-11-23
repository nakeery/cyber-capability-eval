<#
.SYNOPSIS
  List every run_command's command across runs in runs\, separated by run. Read-only.

.DESCRIPTION
  A batch version of watch_steps.ps1: instead of following the newest run live, this scans every run
  already on disk (or a filtered subset) and prints the commands each one sent, in order.

    powershell -NoProfile -File drafts\list_commands.ps1
    powershell -NoProfile -File drafts\list_commands.ps1 -RunId 576337          # one run, by id prefix
    powershell -NoProfile -File drafts\list_commands.ps1 -Newest 5              # the 5 most recently created runs
    powershell -NoProfile -File drafts\list_commands.ps1 -Variant B -Condition hint

  For each matching run it prints a header (run id, variant, condition, how it ended, the run's flag and
  admin password where the manifest has one) and then every step's command, numbered: a run_command's
  command, a submit_flag attempt as "submitted: <flag>", a malformed turn as its recorded error, and
  anything else (text-only, a platform block) as its stop reason. It does not print assistant text or
  tool output; see watch_steps.ps1 for that.

  Terminal control codes are stripped from displayed text, same as watch_steps.ps1, so a recorded command
  cannot repaint your terminal when printed. The flag and password shown are real secrets for that run:
  don't paste this output anywhere a later run's model could read it.
#>
param(
  [string]$RunsDir = (Join-Path (Split-Path -Parent $PSScriptRoot) "runs"),
  [string]$RunId = "",          # a run-id prefix; empty matches every run
  [string]$Variant = "",        # A|B|C|D; empty matches every variant
  [string]$Condition = "",      # no_hint|hint; empty matches either
  [int]$Newest = 0              # 0 = every matching run; otherwise only the N most recently created
)

$ErrorActionPreference = "Stop"
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

function Clean([string]$Text) {
  $t = [regex]::Replace($Text, "\x1B\[[0-9;?]*[ -/]*[@-~]", "")
  [regex]::Replace($t, "[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", "")
}

function Show-Block([string]$First, [string]$Rest, $Text) {
  $lines = (Clean ([string]$Text)) -split "\r\n|\r|\n"
  for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($i -eq 0) { $First + $lines[$i] } else { $Rest + $lines[$i] }
  }
}

function Get-Meta([string]$Dir) {
  foreach ($name in "manifest.json", "manifest.partial.json") {
    $path = Join-Path $Dir $name
    if (Test-Path $path) {
      try { return Get-Content $path -Raw | ConvertFrom-Json } catch { }
    }
  }
  $null
}

if (-not (Test-Path $RunsDir)) { "no runs directory at $RunsDir"; exit 0 }

$dirs = Get-ChildItem $RunsDir -Directory | Where-Object { Test-Path (Join-Path $_.FullName "steps.jsonl") } | Sort-Object CreationTime

$matched = @()
foreach ($dir in $dirs) {
  if ($RunId -and ($dir.Name -notlike "$RunId*")) { continue }
  $meta = Get-Meta $dir.FullName
  if ($Variant -and ($meta.variant -ne $Variant)) { continue }
  if ($Condition -and ($meta.condition -ne $Condition)) { continue }
  $matched += [pscustomobject]@{ Dir = $dir; Meta = $meta }
}
if ($Newest -gt 0) { $matched = $matched | Select-Object -Last $Newest }

if ($matched.Count -eq 0) { "no runs matched"; exit 0 }

foreach ($entry in $matched) {
  $dir = $entry.Dir; $meta = $entry.Meta
  ""
  "== run {0}  variant {1}  condition {2}  ended {3}" -f $dir.Name, $meta.variant, $meta.condition, $meta.termination_reason
  if ($meta.flag) { "   flag:     {0}" -f $meta.flag }
  if ($meta.admin_password) { "   password: {0}" -f $meta.admin_password }

  foreach ($line in (Get-Content (Join-Path $dir.FullName "steps.jsonl"))) {
    if (-not $line.Trim()) { continue }
    try { $s = $line | ConvertFrom-Json } catch { "  step  ?: (a line that is not JSON)"; continue }
    if ($s.tool_name -eq "run_command" -and $s.tool_input) {
      Show-Block ("  step {0,2}: `$ " -f $s.step) "            " $s.tool_input.command
    } elseif ($s.tool_name -eq "submit_flag" -and $s.tool_input) {
      "  step {0,2}: submitted: {1}" -f $s.step, (Clean ([string]$s.tool_input.flag))
    } elseif ($s.tool_call_error) {
      "  step {0,2}: (malformed: {1})" -f $s.step, $s.tool_call_error
    } else {
      "  step {0,2}: (no command -- stop_reason {1})" -f $s.step, $s.stop_reason
    }
  }
}
