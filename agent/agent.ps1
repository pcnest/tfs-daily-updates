# tfs-daily-poc sync agent (PowerShell)
# Purpose: Pull minimal ticket data from TFS 2017 (via WIQL) and push to your public API.
# Run on a Windows machine that already has VPN access to TFS.
# USAGE:
#   1) Update the Variables section below (TFS URL, Collection, Project, PAT, API URL, etc.)
#   2) Save and run:  powershell -ExecutionPolicy Bypass -File .\agent.ps1
#   3) Schedule with Task Scheduler to run every 5-10 minutes.

# ---------- Variables (EDIT THESE) ----------
$TfsUrl        = "https://remote.spdev.us/tfs"
$Collection    = "SupplyPro.Applications"
$Project       = "SupplyPro.Core"
$Team          = "Enterprise Software Team"
$Pat           = "x34cxkcnvd7zuxw6egqyg2yyf6frsbw3vjjnmh37xgar2aopxwqa"   # Read-only PAT is recommended
$WiqlFile      = ".\sample.wiql"            # WIQL file path (relative to this script)
$PublicApiBase = "https://tfs-daily-api.onrender.com"
$PublicApiKey  = "3bded27a3b75ee54e2ae2da4293687c26172d3f551e3584e343c71d399e4054f"
# --------------------------------------------

# ---------- Basics ----------
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$AgentDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$NowUtc   = (Get-Date).ToUniversalTime()

function Write-Log([string]$msg) {
  $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  Write-Host "[$ts] $msg"
}

function Sanitize([object]$v) {
  if ($null -eq $v) { return "" }
  $s = [string]$v
  $s = $s -replace '[\u0000-\u001F\u2028\u2029]', ' '
  $s = $s -replace '[\uD800-\uDFFF]', ' '
  $s = $s.Trim()
  $s = $s -replace '\s{2,}', ' '
  return $s
}

# ---------- last_sync.json (robust) ----------
$SyncFile     = Join-Path $AgentDir "last_sync.json"
$InitialDays  = 14   # initial backfill window

function Get-LastSyncUtc {
  try {
    if (Test-Path $SyncFile) {
      $raw = Get-Content -LiteralPath $SyncFile -Raw
      if (-not [string]::IsNullOrWhiteSpace($raw)) {
        $js = $raw | ConvertFrom-Json
        $candidates = @($js.last_sync_utc, $js.lastSyncUtc, $js.lastSync, $js.sinceUtc, $js.watermark) | Where-Object { $_ }
        foreach ($c in $candidates) {
  if ($c) {
    try {
      $dt = [datetime]$c
      return [datetime]::SpecifyKind($dt, 'Utc')
    } catch { }
  }
}

      }
    }
  } catch {
    Write-Log "[warn] could not parse last_sync.json; using fallback. $_"
  }
  return (Get-Date).ToUniversalTime().AddDays(-$InitialDays)
}

function Save-LastSyncUtc([datetime]$whenUtc) {
  $meta = [ordered]@{
    last_sync_utc  = $whenUtc.ToString('o')
    last_sync_date = $whenUtc.ToString('yyyy-MM-dd')
    note           = 'Updated after delta run'
  }
  $meta | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $SyncFile -Encoding UTF8
  Write-Log ("[delta] watermark updated to {0} (date-only {1})" -f $meta.last_sync_utc, $meta.last_sync_date)
}

$SinceUtc       = Get-LastSyncUtc
$SinceUtcIso    = $SinceUtc.ToUniversalTime().ToString('o')          # for logs / strict filtering
$SinceDateYmd   = $SinceUtc.ToUniversalTime().ToString('yyyy-MM-dd') # for WIQL (date-precision)
Write-Log "[delta] LastSync: $SinceUtcIso (date-only $SinceDateYmd)"

# ---------- TFS helpers ----------
if (-not $Pat) { throw "PAT not set (`$Pat). Provide a Personal Access Token." }
$basic = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$Pat"))
$tfsHeaders = @{ Authorization = "Basic $basic"; Accept = "application/json"; 'Content-Type' = 'application/json' }

function Get-TfsProjectId {
  param([string]$BaseUrl, [string]$Project, [hashtable]$Headers)
  $url = "$BaseUrl/_apis/projects?api-version=2.0"
  $resp = Invoke-RestMethod -Method Get -Uri $url -Headers $Headers
  ($resp.value | Where-Object { $_.name -eq $Project } | Select-Object -First 1).id
}

function Get-TfsTeamId {
  param([string]$BaseUrl, [string]$ProjectId, [string]$Team, [hashtable]$Headers)
  $url = "$BaseUrl/_apis/projects/$ProjectId/teams?api-version=2.0"
  $resp = Invoke-RestMethod -Method Get -Uri $url -Headers $Headers
  ($resp.value | Where-Object { $_.name -eq $Team } | Select-Object -First 1).id
}

# Resolve IDs (if needed for other calls later)
$baseForIds = "$TfsUrl/$Collection"
$projId = Get-TfsProjectId -BaseUrl $baseForIds -Project $Project -Headers $tfsHeaders
if (-not $projId) { throw "Project '$Project' not found under collection '$Collection'." }
$teamId = Get-TfsTeamId -BaseUrl $baseForIds -ProjectId $projId -Team $Team -Headers $tfsHeaders
if (-not $teamId) { throw "Team '$Team' not found in project '$Project'." }

# Current iteration (optional)
try {
  $iterUrl  = "$TfsUrl/$Collection/$Project/$Team/_apis/work/teamsettings/iterations?`$timeframe=current&api-version=2.0"
  $iterResp = Invoke-RestMethod -Method Get -Uri $iterUrl -Headers $tfsHeaders
  if ($iterResp.value -and $iterResp.value.Count -gt 0) {
    $curr = $iterResp.value[0]
    Write-Log "Team '$Team' current iteration: $($curr.name) ($($curr.attributes.startDate) → $($curr.attributes.endDate))"
  } else {
    Write-Log "Team '$Team' current iteration: NONE (check team settings)"
  }
} catch { Write-Log "Warning: Could not fetch team current iteration. $_" }

# ---------- Build WIQL (inject date-only delta) ----------
if (!(Test-Path $WiqlFile)) { Write-Error "WIQL file not found: $WiqlFile"; exit 1 }
$wiqlRaw = Get-Content $WiqlFile -Raw

# Accept either JSON {"query":"..."} or plain WIQL text
$q = $null
try { $maybeJson = $wiqlRaw | ConvertFrom-Json; if ($maybeJson.query) { $q = [string]$maybeJson.query } } catch {}
if (-not $q) { $q = [string]$wiqlRaw }

# Provide date-precision-safe placeholders
$srcDelta = "`r`n    AND Source.[System.ChangedDate] >= '$SinceDateYmd'"
$tgtDelta = "`r`n    AND Target.[System.ChangedDate] >= '$SinceDateYmd'"

$q = $q.Replace('{{SOURCE_DELTA}}', $srcDelta).Replace('{{TARGET_DELTA}}', $tgtDelta)

$wiqlBody = @{ query = $q } | ConvertTo-Json -Depth 3

# Team/project WIQL URL
$wiqlUrl = "$TfsUrl/$Collection/$Project" + ($(if ($Team -and $Team.Trim().Length -gt 0) { "/$Team" } else { "" })) + "/_apis/wit/wiql?api-version=2.0"
Write-Log "Posting WIQL (delta since $SinceDateYmd) to $wiqlUrl ..."

# ---------- Execute WIQL ----------
$wiqlResponse = Invoke-RestMethod -Method Post -Uri $wiqlUrl -Headers $tfsHeaders -Body $wiqlBody -ContentType 'application/json'

$ids = @()
if ($wiqlResponse.workItems) {
  $ids = $wiqlResponse.workItems | ForEach-Object { $_.id } | Select-Object -Unique
} elseif ($wiqlResponse.workItemRelations) {
  $ids = $wiqlResponse.workItemRelations |
    Where-Object { $_.rel -eq 'System.LinkTypes.Hierarchy-Forward' -and $_.source } |
    ForEach-Object { $_.source.id } |
    Sort-Object -Unique
}

if (!$ids -or $ids.Count -eq 0) {
  Write-Log "No work items returned by WIQL (delta)."
  $ids = @()
} else {
  Write-Log "WIQL returned $($ids.Count) IDs (delta)"
}

# ---------- Additional flat WIQL for items directly in current iteration (even without children) ----------
# Build the iteration path (prefer server-provided path; fallback to Project\Name)
$iterPath = $null
try { $iterPath = if ($curr.path) { $curr.path } else { "$Project\$($curr.name)" } } catch { $iterPath = "$Project\$($curr.name)" }

$flatWiql = @"
SELECT [System.Id]
FROM WorkItems
WHERE
  [System.TeamProject] = '$Project'
  AND [System.State] <> 'Removed'
  AND [System.IterationPath] UNDER '$iterPath'
  AND [System.ChangedDate] >= '$SinceDateYmd'
ORDER BY [System.ChangedDate] DESC
"@

$flatBody = @{ query = $flatWiql } | ConvertTo-Json -Depth 3
Write-Log "Posting flat WIQL (iteration UNDER '$iterPath', since $SinceDateYmd) ..."
$flatResp = Invoke-RestMethod -Method Post -Uri $wiqlUrl -Headers $tfsHeaders -Body $flatBody -ContentType 'application/json'

$ids2 = @()
if ($flatResp.workItems) {
  $ids2 = $flatResp.workItems | ForEach-Object { $_.id } | Select-Object -Unique
}
Write-Log "Flat WIQL returned $($ids2.Count) IDs (iteration direct)"

# Merge IDs from link-based and flat queries
if (-not $ids)  { $ids  = @() }
if (-not $ids2) { $ids2 = @() }

$ids = @() + @($ids) + @($ids2)
$ids = $ids | Select-Object -Unique

Write-Log "Total unique IDs after merge: $($ids.Count)"


# ---------- Expand details in batches ----------
function Get-WorkItems($idBatch) {
  if (!$idBatch -or $idBatch.Count -eq 0) { return @() }
  $idList = ($idBatch -join ",")
  $fields = @(
    "System.Id","System.WorkItemType","System.Title","System.State","System.AssignedTo",
    "System.AreaPath","System.IterationPath","System.ChangedDate","System.Tags"
  ) -join ","
  $url = "$TfsUrl/$Collection/_apis/wit/workitems?ids=$idList&fields=$fields&api-version=2.0"
  Write-Log "Fetching details for IDs: $idList"
  $resp = Invoke-RestMethod -Method Get -Uri $url -Headers $tfsHeaders
  return $resp.value
}

$tickets   = @()
$batchSize = 180
for ($i = 0; $i -lt $ids.Count; $i += $batchSize) {
  $batch = $ids[$i..([Math]::Min($i+$batchSize-1, $ids.Count-1))]
  $items = Get-WorkItems $batch
  foreach ($it in $items) {
    $f = $it.fields
    $assigned = ""
    $ass = $f.'System.AssignedTo'
    if ($null -ne $ass) {
      if ($ass -is [string]) { $assigned = $ass }
      elseif ($ass -is [hashtable]) {
        if ($ass['uniqueName'])      { $assigned = [string]$ass['uniqueName'] }
        elseif ($ass['displayName']) { $assigned = [string]$ass['displayName'] }
        elseif ($ass['name'])        { $assigned = [string]$ass['name'] }
      } else {
        if ($ass.PSObject.Properties['uniqueName'])      { $assigned = [string]$ass.uniqueName }
        elseif ($ass.PSObject.Properties['displayName']) { $assigned = [string]$ass.displayName }
        elseif ($ass.PSObject.Properties['name'])        { $assigned = [string]$ass.name }
        else { $assigned = [string]$ass }
      }
    }

    $tickets += [PSCustomObject]@{
      id            = $f."System.Id"
      type          = $f."System.WorkItemType"
      title         = $f."System.Title"
      state         = $f."System.State"
      assignedTo    = (Sanitize $assigned)
      areaPath      = $f."System.AreaPath"
      iterationPath = $f."System.IterationPath"
      changedDate   = $f."System.ChangedDate"
      tags          = $f."System.Tags"
    }
  }
  $types = $tickets | Select-Object -ExpandProperty type -Unique
  Write-Log ("Types seen: " + ($types -join ", "))
}

# ---------- Exact-time delta filter (post-expand) ----------
$exactDelta = $tickets | Where-Object {
  $dt = $null
  try { $dt = [datetime]$_.changedDate } catch { $dt = $null }
  $dt -and $dt.ToUniversalTime() -gt $SinceUtc
}

# ---------- Push to Public API ----------
$pushUrl = "$PublicApiBase/api/sync/tickets"
$headers = @{ 'x-api-key' = $PublicApiKey; 'Content-Type' = 'application/json; charset=utf-8' }
$pushBatchSize = 200

for ($i = 0; $i -lt $exactDelta.Count; $i += $pushBatchSize) {
  $end   = [Math]::Min($i + $pushBatchSize - 1, $exactDelta.Count - 1)
  $chunk = $exactDelta[$i..$end]

  $payloadTickets = @()
  foreach ($t in $chunk) {
    $payloadTickets += [PSCustomObject]@{
      id            = [string]$t.id
      type          = Sanitize $t.type
      title         = Sanitize $t.title
      state         = Sanitize $t.state
      assignedTo    = Sanitize $t.assignedTo
      areaPath      = Sanitize $t.areaPath
      iterationPath = Sanitize $t.iterationPath
      changedDate   = (Get-Date $t.changedDate).ToUniversalTime().ToString("o")
      tags          = Sanitize $t.tags
    }
  }

  $obj = @{ source = 'tfs-agent'; tickets = $payloadTickets; pushedAt = (Get-Date).ToUniversalTime().ToString('o') }
  $json  = $obj | ConvertTo-Json -Depth 8
  $bytes = [Text.Encoding]::UTF8.GetBytes($json)

  Write-Log "Pushing tickets $i..$end ($($payloadTickets.Count)) to $pushUrl ..."
  try {
    $result = Invoke-RestMethod -Method Post -Uri $pushUrl -Headers $headers -Body $bytes
    Write-Log "Chunk push result: $($result.status); count=$($result.count)"
  } catch {
    Write-Error $_.Exception.Message
    if ($_.Exception.Response) {
      $reader = New-Object IO.StreamReader($_.Exception.Response.GetResponseStream())
      $reader.BaseStream.Position = 0
      $reader.DiscardBufferedData()
      $responseBody = $reader.ReadToEnd()
      Write-Error "Server said: $responseBody"
    }
    $dumpFile = "payload-failed-$i-$end.json"
    [IO.File]::WriteAllBytes($dumpFile, $bytes)
    Write-Error "Saved failing payload to $dumpFile"
    exit 1
  }
}

Write-Log "All chunks pushed. Total tickets sent: $($exactDelta.Count) (from $($tickets.Count) fetched)"

# ---------- Advance watermark ----------
$maxChangedUtc = $null
foreach ($it in $tickets) {
  $cUtc = $null
  try { $cUtc = ([datetime]$it.changedDate).ToUniversalTime() } catch { $cUtc = $null }
  if ($cUtc -and (-not $maxChangedUtc -or $cUtc -gt $maxChangedUtc)) { $maxChangedUtc = $cUtc }
}

if ($maxChangedUtc) {
  $safeMark = $maxChangedUtc.AddMinutes(-2)
  if ($safeMark -lt $SinceUtc) { $safeMark = $SinceUtc }
  Save-LastSyncUtc $safeMark
  Write-Log "[delta] advanced LastSyncUtc → $($safeMark.ToString('o')) (from newest ChangedDate)"
} else {
  # No items came back — still advance to now to avoid re-query loops
  Save-LastSyncUtc $NowUtc
  Write-Log "[delta] no items changed; watermark set to now ($($NowUtc.ToString('o')))"
}
