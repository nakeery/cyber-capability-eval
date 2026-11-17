<#
.SYNOPSIS
  Start, stop or inspect the local model server (DECISIONS.md D-067, D-068, D-069).

.DESCRIPTION
  The server is started by the OPERATOR with this script, never by the harness: the harness is the server's only client.

    powershell -File harness\local_server.ps1 start
    powershell -File harness\local_server.ps1 status
    powershell -File harness\local_server.ps1 stop

  The command line comes from harness\local_pin.json (its `server_flags`), so the pin is the single source of truth for how
  the server runs. This script adds only the paths: the weights file named by the pin, the API-key file, and the CUDA DLL
  directory. `start` refuses to run if something already listens on the port, and after starting it checks that the process
  listens on the loopback address ONLY; if it does not, the process is killed and the script fails. `stop` kills a process only if
  its executable is the pinned runtime, so a stale pid file can never end an unrelated process.

  Layout under -Root (default G:\model-eval-local), created by hand (D-067):
    runtime\llama-b12478-cuda12.4\llama-server.exe     the extracted llama.cpp release
    runtime\cudart-12.4\                               the CUDA runtime DLLs (put on PATH for the server only)
    models\qwen3-8b-q4_k_m\Qwen3-8B-Q4_K_M.gguf       the weights
    server\api_key.txt                                 the bearer key (one line); server\pid.txt, server\server.*.log are written here
#>
param(
  [Parameter(Mandatory = $true, Position = 0)][ValidateSet("start", "stop", "status")][string]$Action,
  [string]$Root = "G:\model-eval-local",
  [string]$Runtime = "llama-b12478-cuda12.4",
  [string]$ModelDir = "qwen3-8b-q4_k_m"
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$pin = Get-Content (Join-Path $repo "harness\local_pin.json") -Raw | ConvertFrom-Json
$exe = Join-Path $Root "runtime\$Runtime\llama-server.exe"
$weights = Join-Path $Root "models\$ModelDir\$($pin.weights_file)"
$serverDir = Join-Path $Root "server"
$keyFile = Join-Path $serverDir "api_key.txt"
$pidFile = Join-Path $serverDir "pid.txt"

# The port is whatever the pin's flags say.
$flags = @($pin.server_flags)
$port = [int]$flags[[array]::IndexOf($flags, "--port") + 1]

function Get-Listeners([int]$ProcessId) {
  Get-NetTCPConnection -OwningProcess $ProcessId -State Listen -ErrorAction SilentlyContinue
}

function Get-ServerProcess {
  # The pid file names a candidate; it only counts if that process is the pinned runtime.
  if (Test-Path $pidFile) {
    $recorded = [int](Get-Content $pidFile | Select-Object -First 1)
    $p = Get-Process -Id $recorded -ErrorAction SilentlyContinue
    if ($p -and $p.Path -eq $exe) { return $p }
  }
  return $null
}

switch ($Action) {
  "status" {
    $p = Get-ServerProcess
    if (-not $p) { "stopped (no pinned llama-server process)"; break }
    "running: pid $($p.Id), started $($p.StartTime)"
    Get-Listeners $p.Id | ForEach-Object { "  listening on $($_.LocalAddress):$($_.LocalPort)" }
    "  /health: " + (& curl.exe -s --noproxy "*" "http://127.0.0.1:$port/health")
  }

  "stop" {
    $p = Get-ServerProcess
    if (-not $p) { "nothing to stop (no pinned llama-server process)"; break }
    Stop-Process -Id $p.Id
    Start-Sleep -Seconds 3
    if (Get-Process -Id $p.Id -ErrorAction SilentlyContinue) { throw "pid $($p.Id) did not stop" }
    Remove-Item $pidFile -ErrorAction SilentlyContinue
    "stopped pid $($p.Id)"
  }

  "start" {
    foreach ($required in @($exe, $weights, $keyFile)) { if (-not (Test-Path $required)) { throw "missing: $required" } }
    if (Get-ServerProcess) { throw "already running (use stop first)" }
    if (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue) { throw "something else already listens on port $port" }

    # The pin's flags, with the key-file placeholder filled in, plus the weights.
    $arguments = @("-m", $weights) + ($flags | ForEach-Object { if ($_ -eq "<file>") { $keyFile } else { $_ } })
    $env:PATH = (Join-Path $Root "runtime\cudart-12.4") + ";" + $env:PATH
    $p = Start-Process -FilePath $exe -ArgumentList $arguments -PassThru -WindowStyle Hidden `
         -RedirectStandardOutput (Join-Path $serverDir "server.out.log") -RedirectStandardError (Join-Path $serverDir "server.err.log")
    $p.Id | Out-File $pidFile -Encoding ascii

    # Wait for the model to load.
    $ready = $false
    for ($i = 0; $i -lt 90; $i++) {
      if ($p.HasExited) { throw "the server exited during start-up: see $serverDir\server.err.log" }
      if ((& curl.exe -s --noproxy "*" "http://127.0.0.1:$port/health") -match '"ok"') { $ready = $true; break }
      Start-Sleep -Seconds 2
    }
    if (-not $ready) { Stop-Process -Id $p.Id; throw "the server did not become ready in 180 s" }

    # The bind check: every listening socket of the process must be on the loopback address.
    $listeners = @(Get-Listeners $p.Id)
    $wide = @($listeners | Where-Object { $_.LocalAddress -notin @("127.0.0.1", "::1") })
    if ($listeners.Count -eq 0 -or $wide.Count -gt 0) {
      Stop-Process -Id $p.Id
      throw ("the server listens beyond loopback ({0}); it was stopped" -f (($wide | ForEach-Object { "$($_.LocalAddress):$($_.LocalPort)" }) -join ", "))
    }
    "started pid $($p.Id); listening on " + (($listeners | ForEach-Object { "$($_.LocalAddress):$($_.LocalPort)" }) -join ", ") + " (loopback only)"
  }
}
