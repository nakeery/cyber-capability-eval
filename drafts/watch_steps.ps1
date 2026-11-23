<#
.SYNOPSIS
  Follow the newest run in runs\ and switch by itself when a new run starts. Read-only.

.DESCRIPTION
  Start it in a second terminal, before or during a run:

    powershell -NoProfile -File drafts\watch_steps.ps1
    powershell -NoProfile -File drafts\watch_steps.ps1 -NewOnly        # ignore runs that already exist
    powershell -NoProfile -File drafts\watch_steps.ps1 -FullOutput     # raw tool output instead of what the model saw

  It polls runs\ once a second. The newest run directory (by creation time) is the one followed.

  For each run it prints a header with the variant, the condition and the run's FLAG and ADMIN PASSWORD (read from the
  run's manifest), then one block per step:

    HH:mm:ss  step N  <tool>  stop=...  exit=...  timeout=...  in=...  out=...      (summary line)
        says: <the assistant's text, if any>
        $ <the command the model ran>        (or "submitted: <flag>", or the error and raw call of a malformed call)
        | <the tool's output>

  The output shown is `output_sent_to_model`: what the model actually saw (control codes stripped, special-token text
  neutralized, cut to head and tail if long). -FullOutput shows `output_full`, the raw output, instead. Either way,
  terminal control codes are removed for display so a command's output cannot repaint your terminal.

  A step whose stop reason is model_context_window_exceeded or content_filtered was ended by the harness or the platform:
  its text is not the model's own words (D-075, harness/step_kind.py).

  The time shown is when the watcher saw the step, not when the step ran. When a run's manifest.json appears, it prints
  how the run ended. Ctrl+C stops the watcher.

  It only reads files on the host, opened for shared reading, and the model never sees this terminal: the model's
  whole view is what the harness sends it. So printing anything here cannot change what the model does. The flag
  and password are per-run random values, but they are real for that run: do not paste this output anywhere a later
  run's model could read it.
#>
param(
  [string]$RunsDir = (Join-Path (Split-Path -Parent $PSScriptRoot) "runs"),
  [double]$PollSeconds = 1,
  [switch]$NewOnly,
  [switch]$FullOutput
)

$ErrorActionPreference = "Stop"
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }    # a command can hold non-ASCII text

$script:dir = $null           # the run directory being followed
$script:reader = $null        # a shared-read reader on its steps.jsonl
$script:partial = ""          # an incomplete last line, kept until its newline arrives
$script:headerShown = $false
$script:endShown = $false

function Get-NewestRun {
  if (-not (Test-Path $RunsDir)) { return $null }
  Get-ChildItem $RunsDir -Directory | Sort-Object CreationTime | Select-Object -Last 1
}

function Get-Meta([string]$Dir) {
  foreach ($name in "manifest.json", "manifest.partial.json") {
    $path = Join-Path $Dir $name
    if (Test-Path $path) {
      try {
        $m = Get-Content $path -Raw | ConvertFrom-Json
        return [pscustomobject]@{ found = $true; variant = $m.variant; condition = $m.condition
                                  flag = $m.flag; password = $m.admin_password; ended = $m.termination_reason }
      } catch { }      # caught mid-write: try again on the next poll
    }
  }
  [pscustomobject]@{ found = $false; variant = "?"; condition = "?"; flag = "?"; password = "?"; ended = $null }
}

function Show-Header {
  $meta = Get-Meta $script:dir
  $hasSteps = Test-Path (Join-Path $script:dir "steps.jsonl")
  if (-not $meta.found -and -not $hasSteps) { return }      # the run's files are not there yet: try again next poll
  ""
  "== run {0}  variant {1}  condition {2}  (seen {3})" -f (Split-Path $script:dir -Leaf), $meta.variant, $meta.condition, (Get-Date -Format HH:mm:ss)
  "   flag:     {0}" -f $meta.flag
  "   password: {0}" -f $meta.password
  $script:headerShown = $true
}

function Clean([string]$Text) {
  # Display only: drop ANSI escape sequences and other control characters (tab and newline stay), so that the text
  # of a run cannot repaint or reconfigure this terminal.
  $t = [regex]::Replace($Text, "\x1B\[[0-9;?]*[ -/]*[@-~]", "")
  [regex]::Replace($t, "[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", "")
}

function Show-Block([string]$First, [string]$Rest, $Text) {
  # The text's lines, the first behind $First and the others behind $Rest. A bare carriage return (a progress bar)
  # counts as a line break so it cannot overwrite the line before it.
  $lines = (Clean ([string]$Text)) -split "\r\n|\r|\n"
  for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($i -eq 0) { $First + $lines[$i] } else { $Rest + $lines[$i] }
  }
}

function Show-Step([string]$Line) {
  $now = Get-Date -Format HH:mm:ss
  try { $s = $Line | ConvertFrom-Json } catch { "{0}  (a line that is not JSON, {1} chars)" -f $now, $Line.Length; return }
  "{0}  step {1,2}  {2,-12} stop={3,-12} exit={4} timeout={5} in={6} out={7}" -f $now, $s.step, $s.tool_name, $s.stop_reason, $s.exit_code, $s.timed_out, $s.input_tokens, $s.output_tokens
  if ("$($s.assistant_text)".Trim()) { Show-Block "    says: " "          " $s.assistant_text }
  if ($s.tool_call_error) { "    tool_call_error: {0}" -f (Clean ([string]$s.tool_call_error)) }
  if ($s.tool_name -eq "run_command" -and $s.tool_input) {
    Show-Block "    `$ " "      " $s.tool_input.command
  } elseif ($s.tool_name -eq "submit_flag" -and $s.tool_input) {
    "    submitted: {0}" -f (Clean ([string]$s.tool_input.flag))
  } elseif (-not $s.tool_name -and $s.raw_tool_use) {
    $raw = $s.raw_tool_use
    if ($raw -isnot [string]) { $raw = $raw | ConvertTo-Json -Compress -Depth 10 }
    "    raw call: {0}" -f (Clean $raw)
  }
  $output = if ($FullOutput) { $s.output_full } else { $s.output_sent_to_model }
  if ("$output".Length -gt 0) {
    Show-Block "    | " "    | " $output
  } elseif ($s.tool_name) {
    "    | (no output)"
  }
}

function Read-New {
  if (-not $script:reader) { return }
  $chunk = $script:reader.ReadToEnd()
  if (-not $chunk) { return }
  $lines = ($script:partial + $chunk) -split "`n"
  $script:partial = $lines[$lines.Count - 1]
  for ($i = 0; $i -lt $lines.Count - 1; $i++) {
    if ($lines[$i].Trim()) { Show-Step $lines[$i] }
  }
}

function Open-Reader {
  $path = Join-Path $script:dir "steps.jsonl"
  if (-not (Test-Path $path)) { return }
  # The harness holds the file open for appending: share for read and write, so this never blocks it.
  $share = [System.IO.FileShare]"ReadWrite, Delete"
  $stream = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, $share)
  $script:reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::UTF8)
}

function Switch-To($Run) {
  if ($script:reader) { Read-New; $script:reader.Dispose() }      # drain the old run before leaving it
  $script:dir = $Run.FullName
  $script:reader = $null
  $script:partial = ""
  $script:headerShown = $false
  $script:endShown = $false
}

$baseline = $null
if ($NewOnly) {
  $existing = Get-NewestRun
  if ($existing) { $baseline = $existing.FullName }
}

"watching $RunsDir  (Ctrl+C to stop)" + $(if ($baseline) { "; ignoring runs that already exist" } else { "" }) + $(if ($FullOutput) { "; showing raw tool output" } else { "" })
try {
  while ($true) {
    $newest = Get-NewestRun
    if ($newest -and $newest.FullName -ne $script:dir -and $newest.FullName -ne $baseline) { Switch-To $newest }
    if ($script:dir) {
      if (-not $script:headerShown) { Show-Header }
      if ($script:headerShown) {
        if (-not $script:reader) { Open-Reader }
        Read-New
        if (-not $script:endShown -and (Test-Path (Join-Path $script:dir "manifest.json"))) {
          Read-New
          "== ended: {0}" -f (Get-Meta $script:dir).ended
          $script:endShown = $true
        }
      }
    }
    Start-Sleep -Milliseconds ([int]($PollSeconds * 1000))
  }
} finally {
  if ($script:reader) { $script:reader.Dispose() }
}
