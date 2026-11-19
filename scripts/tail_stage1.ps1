# Tails the current baseline trial's stage-1 sqlmap log, switching automatically whenever a newer
# run starts under runs/ -- mirrors drafts/watch_steps.ps1's own newest-run-wins polling loop
# (Get-NewestRun / Switch-To), adapted to this script's plain-text log instead of steps.jsonl. Run
# ids are fresh uuid4 hex per trial (baseline/run_baseline.py's main()), so "newest by creation time"
# is the only handle available -- there is no way to know a run's id in advance.
#
# Opens the file with FileShare "ReadWrite, Delete" instead of Get-Content -Wait, same reasoning as
# drafts/watch_steps.ps1's Open-Reader: run_stage1 holds this file open the whole time it's writing
# to it (stdout_to, then appending stderr once sqlmap exits), so a plain Get-Content -Wait risks a
# "being used by another process" sharing error on Windows instead of just waiting for new bytes.
#
# Usage (from the repo root, in a second terminal; start it any time, before or during a trial):
#   .\scripts\tail_stage1.ps1
#
# Ctrl+C stops it.

param(
    [string]$RunsDir = (Join-Path $PSScriptRoot "..\runs"),
    [double]$PollSeconds = 1
)

$script:dir = $null         # the run directory currently being watched (its full path)
$script:reader = $null      # an open StreamReader on that run's stage1_sqlmap.log, once it exists

function Get-NewestRun {
    Get-ChildItem $RunsDir -Directory -ErrorAction SilentlyContinue |
        Sort-Object CreationTime -Descending | Select-Object -First 1
}

function Read-New {
    if (-not $script:reader) { return }
    $chunk = $script:reader.ReadToEnd()
    if ($chunk) { Write-Host -NoNewline $chunk }
}

function Switch-To([string]$NewDir) {
    if ($script:reader) { Read-New; $script:reader.Dispose() }   # drain and close the old run's log first
    $script:dir = $NewDir
    $script:reader = $null
    Write-Host "`nWatching run: $(Split-Path $NewDir -Leaf)"
}

function Open-Reader {
    $path = Join-Path $script:dir "stage1_sqlmap.log"
    if (-not (Test-Path $path)) { return }
    # Share for read AND write (and delete): run_stage1 still holds this same file open while it
    # writes to it, and this must never collide with that.
    $share = [System.IO.FileShare]"ReadWrite, Delete"
    $stream = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, $share)
    $script:reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::UTF8)
    # Show whatever's already in the file (last ~20 lines) before following new bytes as they land.
    $existing = $script:reader.ReadToEnd()
    if ($existing) {
        ($existing -split "\r\n|\r|\n") | Select-Object -Last 20 | ForEach-Object { $_ }
    }
}

Write-Host "Watching $RunsDir for a run's stage1_sqlmap.log (Ctrl+C to stop) ..."
try {
    while ($true) {
        $newest = Get-NewestRun
        if ($newest -and $newest.FullName -ne $script:dir) { Switch-To $newest.FullName }
        if ($script:dir) {
            if (-not $script:reader) { Open-Reader } else { Read-New }
        }
        Start-Sleep -Milliseconds ([int]($PollSeconds * 1000))
    }
} finally {
    if ($script:reader) { $script:reader.Dispose() }
}
