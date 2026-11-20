$cells = foreach ($v in 'A','B','C','D') { foreach ($c in 'no_hint','hint') { 1..3 | ForEach-Object { ,@($v,$c) } } };
$randSeed = Get-Random -InputObject 1..10000
Write-Host "Random seed: $randSeed"
$order = Get-Random -InputObject $cells -Count $cells.Count -SetSeed $randSeed;
$i = 0;
foreach ($cell in $order) { $i++; Write-Host "== $i/24: $($cell[0]) $($cell[1])"; .venv/Scripts/python harness/run.py run $cell[0] $cell[1] --order-seed $randSeed; if ($LASTEXITCODE -ne 0) { Write-Host "exit $LASTEXITCODE on run $i with seed $randSeed" } }