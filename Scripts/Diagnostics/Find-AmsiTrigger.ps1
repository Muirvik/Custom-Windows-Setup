# Find-AmsiTrigger.ps1
# Doel: uitzoeken welk deel van een script door Windows Defender (AMSI) wordt geblokkeerd.
# Dit script voert NIETS van de setup uit. Elk testbestand bevat alleen een functie die nooit wordt aangeroepen;
# Defender scant de inhoud wel wanneer het bestand wordt geladen.
# Gebruik (gewone PowerShell, admin is niet nodig):
#   Set-ExecutionPolicy -Scope Process Bypass -Force
#   .\Scripts\Diagnostics\Find-AmsiTrigger.ps1
$ErrorActionPreference = 'Continue'
$repoRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
$workDir = Join-Path ([IO.Path]::GetTempPath()) 'cws-amsi-test'
New-Item -Path $workDir -ItemType Directory -Force | Out-Null

function Test-CwsBlocked {
    param([Parameter(Mandatory)][string]$Text)
    $file = Join-Path $workDir ('t{0}.ps1' -f [guid]::NewGuid().ToString('N'))
    try {
        Set-Content -LiteralPath $file -Value ("function Test-CwsWrapper {`r`n" + $Text + "`r`n}`r`n") -Encoding UTF8 -ErrorAction Stop
        & $file 2>&1 | Out-Null
        return $false
    } catch {
        return ($_.FullyQualifiedErrorId -like '*Malicious*' -or $_.Exception.Message -like '*malicious*' -or $_.Exception.Message -like '*antivirus*')
    } finally {
        Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
    }
}

$files = Get-ChildItem -Path $repoRoot -Recurse -Filter '*.ps1' -File | Where-Object { $_.FullName -notlike '*Diagnostics*' }
foreach ($scriptFile in $files) {
    $rel = $scriptFile.FullName.Substring($repoRoot.Length).TrimStart('\','/')
    $text = Get-Content -LiteralPath $scriptFile.FullName -Raw
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$null, [ref]$null)
    $stmts = @($ast.EndBlock.Statements)
    if ($stmts.Count -eq 0) { Write-Host "[-]  $rel : geen statements" ; continue }

    $last = $stmts.Count - 1
    if (-not (Test-CwsBlocked -Text $text.Substring(0, $stmts[$last].Extent.EndOffset))) {
        Write-Host "[OK] $rel : niet geblokkeerd" -ForegroundColor Green
        continue
    }
    # Binaire zoektocht naar het eerste statement waarbij de verzameling geblokkeerd wordt.
    $lo = 0; $hi = $last
    while ($lo -lt $hi) {
        $mid = [int][Math]::Floor(($lo + $hi) / 2)
        if (Test-CwsBlocked -Text $text.Substring(0, $stmts[$mid].Extent.EndOffset)) { $hi = $mid } else { $lo = $mid + 1 }
    }
    $trigger = $stmts[$lo]
    Write-Host "[GEBLOKKEERD] $rel : regel $($trigger.Extent.StartLineNumber) t/m $($trigger.Extent.EndLineNumber)" -ForegroundColor Red
    $snippet = ($trigger.Extent.Text -split "`r?`n") | Select-Object -First 12
    $snippet | ForEach-Object { Write-Host ("      " + $_) -ForegroundColor DarkYellow }
    # Controleer of dit statement ook los (zonder het voorgaande) wordt geblokkeerd.
    $alone = Test-CwsBlocked -Text $trigger.Extent.Text
    Write-Host ("      Los getest: " + $(if ($alone) { 'ook geblokkeerd' } else { 'alleen geblokkeerd in combinatie met eerdere code' }))
}
Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "`nKlaar. Stuur de regels met [GEBLOKKEERD] en de getoonde code."
