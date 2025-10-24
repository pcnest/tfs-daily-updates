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
# $PublicApiBase = "http://localhost:8080"
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
# If last_sync.json is somehow in the FUTURE, clamp it to now (prevents empty deltas)
if ($SinceUtc -gt $NowUtc) {
  Write-Log "[delta] LastSync is in the FUTURE ($($SinceUtc.ToString('o'))); clamping to now."
  $SinceUtc = $NowUtc
}

$OverlapMinutes = 5   # <<< you can change to 2–10 mins if you like
$EffSinceUtc    = $SinceUtc.AddMinutes(-$OverlapMinutes)

$SinceUtcIso    = $EffSinceUtc.ToUniversalTime().ToString('o')           # for exact-time post-filter
$SinceDateYmd   = $EffSinceUtc.ToUniversalTime().ToString('yyyy-MM-dd')  # date-precision for WIQL
Write-Log "[delta] LastSync(base)=$($SinceUtc.ToString('o')); using effective since=$SinceUtcIso (window ${OverlapMinutes}m; date-only $SinceDateYmd)"


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
$currentIterName = [string]$curr.name
$currentIterPath = [string]$curr.path  # <<< ADD THIS (full path like 'SupplyPro.Core\2025\Sprint 400')
Write-Log ("Team '{0}' current iteration: {1} ({2} -> {3})" -f $Team, $currentIterName, $curr.attributes.startDate, $curr.attributes.endDate)


  } else {
    $currentIterName = ""
    $currentIterPath = ""
  Write-Log ("Team '{0}' current iteration: NONE (check team settings)" -f $Team)
  }
} catch { $currentIterName = ""
$currentIterPath = ""
  Write-Log ("Warning: Could not fetch team current iteration. {0}" -f $_) }

# ---------- Build + Execute WIQL (A + B) ----------
# We will run two WIQLs and merge IDs:
#  A) PBIs & Bugs in @CurrentIteration
#  B) Parents of Tasks in @CurrentIteration

# Use TEAM-level WIQL route so @CurrentIteration resolves for the team
$teamSeg = [uri]::EscapeDataString($Team)   # e.g., "Enterprise%20Software%20Team"
$wiqlUrl = "$TfsUrl/$Collection/$Project/$teamSeg/_apis/wit/wiql?api-version=2.0"


# Read the two WIQL files and substitute the delta timestamp (use your existing $SinceUtcIso)
# NOTE: $WiqlFile already points to .\sample.wiql
$qA = (Get-Content -Raw -Encoding UTF8 $WiqlFile) -replace '\{SINCE_ISO\}', $SinceDateYmd
$qBPath = Join-Path $PSScriptRoot 'sample_links.wiql'
if (!(Test-Path $qBPath)) { Write-Error "Missing WIQL file: $qBPath"; exit 1 }
$qB = (Get-Content -Raw -Encoding UTF8 $qBPath) -replace '\{SINCE_ISO\}', $SinceDateYmd

# Helper: POST WIQL as UTF-8 JSON bytes; avoid duplicate Content-Type in headers
function Invoke-Wiql([string]$wiqlText) {
  $body  = @{ query = $wiqlText } | ConvertTo-Json -Depth 3
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($body)
  if ($tfsHeaders.ContainsKey('Content-Type')) { $tfsHeaders.Remove('Content-Type') }
  return Invoke-RestMethod -Method Post -Uri $wiqlUrl -Headers $tfsHeaders `
         -Body $bytes -ContentType 'application/json; charset=utf-8'
}

# Run Query A
Write-Log "Posting WIQL A (PBIs/Bugs in @CurrentIteration, since $SinceUtcIso)..."
$respA = Invoke-Wiql $qA
$idsA  = @()
if ($respA.workItems) { $idsA = $respA.workItems | ForEach-Object { $_.id } }
Write-Log "WIQL A returned $($idsA.Count) id(s)."

# Run Query B
Write-Log "Posting WIQL B (Parents of Tasks in @CurrentIteration, since $SinceUtcIso)..."
$respB = Invoke-Wiql $qB
$idsB  = @()
if ($respB.workItemRelations) {
  $idsB = $respB.workItemRelations |
          Where-Object { $_.source -and $_.target } |
          ForEach-Object { $_.source.id } |
          Select-Object -Unique
}
Write-Log "WIQL B returned $($idsB.Count) parent id(s)."

# Merge & dedupe → put into $ids (so your next section can reuse it as-is)
$ids = ($idsA + $idsB) | Sort-Object -Unique
if (!$ids -or $ids.Count -eq 0) {
  Write-Log "No work items returned by WIQL (A+B delta)."
  $ids = @()
} else {
  Write-Log "Merged unique ids: $($ids.Count)."
}
# ---------- END (Build + Execute WIQL A+B) ----------

# === POST current iteration (robust, ASCII-only) ===
$iterUrl = ($PublicApiBase.TrimEnd('/')) + '/api/iteration/current'

$iterHeaders = @{}
if ($PublicApiKey -and $PublicApiKey.Trim()) { $iterHeaders['x-api-key'] = $PublicApiKey.Trim() }

if ([string]::IsNullOrWhiteSpace($PublicApiBase) -or $iterUrl -notmatch '^https?://') {
  Write-Warning ("[iter] Skipping POST - invalid PublicApiBase: '{0}'" -f $PublicApiBase)
}
elseif ([string]::IsNullOrWhiteSpace($currentIterName)) {
  Write-Log '[iter] Skipping POST - no current iteration name resolved.'
}
else {
  $iterPayload = [pscustomobject]@{
    name = $currentIterName
    team = $Team
    at   = (Get-Date).ToString('o')
  } | ConvertTo-Json -Depth 5 -Compress

  try {
    Write-Log ("[iter] POST {0} name='{1}'" -f $iterUrl, $currentIterName)
    $iterResp = Invoke-RestMethod -Uri $iterUrl -Method Post -Headers $iterHeaders `
                -Body $iterPayload -ContentType 'application/json' -TimeoutSec 20 -ErrorAction Stop
    Write-Log '[iter] OK'
  }
  catch {
  $msg    = $_.Exception.Message
  $detail = $_.ErrorDetails.Message
  $body   = ''

  # Try to read the HTTP response body (useful if your API returns JSON error text)
  if ($_.Exception -and $_.Exception.Response) {
    try {
      $sr = New-Object IO.StreamReader($_.Exception.Response.GetResponseStream())
      $body = $sr.ReadToEnd()
    } catch { }
  }

  $tail = ''
  if ($detail) { $tail = ' - ' + $detail }
  elseif ($body) { $tail = ' - ' + $body }

  Write-Warning ("[iter] POST failed: {0}{1}" -f $msg, $tail)
}
}

# ---- Build FULL presence scope (no date filter) ----
# Re-read the WIQL files but strip the ChangedDate constraint by substituting a very old date.
# Using '1900-01-01' effectively includes everything in the current iteration.
$qA_full = (Get-Content -Raw -Encoding UTF8 $WiqlFile) -replace '\{SINCE_ISO\}', '1900-01-01'
$qB_full = (Get-Content -Raw -Encoding UTF8 (Join-Path $PSScriptRoot 'sample_links.wiql')) -replace '\{SINCE_ISO\}', '1900-01-01'

Write-Log "Posting WIQL A (FULL scope, no date limit)..."
$respA_full = Invoke-Wiql $qA_full
$idsA_full  = if ($respA_full.workItems) { $respA_full.workItems | ForEach-Object { $_.id } } else { @() }
Write-Log "WIQL A (FULL) returned $($idsA_full.Count) id(s)."

Write-Log "Posting WIQL B (FULL scope, no date limit)..."
$respB_full = Invoke-Wiql $qB_full
$idsB_full  = @()
if ($respB_full.workItemRelations) {
  $idsB_full = $respB_full.workItemRelations |
               Where-Object { $_.source -and $_.target } |
               ForEach-Object { $_.source.id } |
               Select-Object -Unique
}
Write-Log "WIQL B (FULL) returned $($idsB_full.Count) parent id(s)."

$idsFull = ($idsA_full + $idsB_full) | Sort-Object -Unique
if ($idsFull -contains 191687) { Write-Log "Sanity: 191687 is in FULL scope TRUE" } else { Write-Log "Sanity: 191687 NOT in FULL scope FALSE" }

Write-Log "FULL presence scope has $($idsFull.Count) id(s)."

# ---- Fetch server live IDs for this sprint and compute "missing" ----
try {
  $iterNameEnc = [uri]::EscapeDataString($currentIterName)
  $liveUrl     = "$PublicApiBase/api/iteration/$iterNameEnc/live-ids?types=default"
  $liveResp    = Invoke-RestMethod -Method Get -Uri $liveUrl -Headers @{ 'x-api-key' = $PublicApiKey }
  $serverLive  = @()
  if ($liveResp -and $liveResp.ids) { $serverLive = @($liveResp.ids) }
  $missingIds  = @()
  foreach ($id in $idsFull) {
    if ($serverLive -notcontains ([string]$id)) { $missingIds += $id }
  }
  Write-Log ("Backfill: {0} id(s) are missing on server" -f $missingIds.Count)
} catch {
  Write-Warning "Could not fetch live IDs from server: $($_.Exception.Message)"; $missingIds = @()
}


# ---- END build FULL presence scope ----

# Choose which IDs to expand: delta if we have any, else full scope
if ($ids.Count -gt 0) {
  $expandIds = ($ids + $missingIds) | Sort-Object -Unique
  $src = ('delta' + ($(if ($missingIds.Count -gt 0) { '+missing' } else { '' })))
} else {
  $expandIds = $idsFull
  $src = 'full'
}
Write-Log ("Expanding details for {0} id(s) (source: {1})" -f $expandIds.Count, $src)




# ---------- Expand details in batches ----------
function Get-WorkItems($idBatch) {
  if (!$idBatch -or $idBatch.Count -eq 0) { return @() }
  $idList = ($idBatch -join ",")
    $fields = @(
    "System.Id",
    "System.WorkItemType",
    "System.Title",
    "System.State",
    "System.Reason",
    "Microsoft.VSTS.Common.Priority",
    "Microsoft.VSTS.Common.Severity",
    "System.AssignedTo",
    "System.AreaPath",
    "System.IterationPath",
    "System.CreatedDate",
    "System.ChangedDate",
    "Microsoft.VSTS.Common.StateChangeDate",
    "System.Tags",
    "Microsoft.VSTS.Build.FoundIn",
    "Microsoft.VSTS.Build.IntegrationBuild",
    "Microsoft.VSTS.Scheduling.Effort"
  ) -join ","

  # Fetch ALL fields + relations (TFS 2017 forbids fields= with $expand=Relations)
$url = "$TfsUrl/$Collection/_apis/wit/workitems?ids=$idList&api-version=2.0&`$expand=Relations"


  Write-Log "Fetching details for IDs: $idList"
  $resp = Invoke-RestMethod -Method Get -Uri $url -Headers $tfsHeaders
  return $resp.value
}

$tickets   = @()
$batchSize = 180
for ($i = 0; $i -lt $expandIds.Count; $i += $batchSize) {
  $batch = $expandIds[$i..([Math]::Min($i+$batchSize-1, $expandIds.Count-1))]
  $items = Get-WorkItems $batch
  foreach ($it in $items) {
  $f = $it.fields

  # --- assignedTo normalization (keep your existing logic) ---
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

  # --- relations → relatedLinkCount (exclude Hierarchy) ---
  $rels = @($it.relations)
  $related = $rels | Where-Object {
    $_.rel -like 'System.LinkTypes.*' -and $_.rel -notmatch 'Hierarchy'
  }
  $relatedLinkCount = @($related).Count

  # --- capture all finalized raw fields ---
  $tickets += [PSCustomObject]@{
    id                 = $f."System.Id"
    type               = $f."System.WorkItemType"
    title              = $f."System.Title"
    state              = $f."System.State"
    reason             = $f."System.Reason"
    priority           = $f."Microsoft.VSTS.Common.Priority"
    severity           = $f."Microsoft.VSTS.Common.Severity"         # Bugs only
    assignedTo         = (Sanitize $assigned)
    areaPath           = $f."System.AreaPath"
    iterationPath      = $f."System.IterationPath"
    createdDate        = $f."System.CreatedDate"
    changedDate        = $f."System.ChangedDate"
    stateChangeDate    = $f."Microsoft.VSTS.Common.StateChangeDate"
    tags               = $f."System.Tags"
    foundInBuild       = $f."Microsoft.VSTS.Build.FoundIn"
    integratedInBuild  = $f."Microsoft.VSTS.Build.IntegrationBuild"
    relatedLinkCount   = $relatedLinkCount
    effort             = $f."Microsoft.VSTS.Scheduling.Effort"       # PBIs only
  }
}

  $types = $tickets | Select-Object -ExpandProperty type -Unique
  Write-Log ("Types seen: " + ($types -join ", "))
}

# ---------- Exact-time delta filter (post-expand) ----------
# Items to push this run:
#  1) changed/created after effective since, OR
#  2) not present on server yet (missing backfill)
# safer parsing for ISO timestamps (handles Z and offsets cleanly)
function AsUtc([object]$v) {
  if (-not $v) { return $null }
  try { return ([datetimeoffset]::Parse([string]$v)).UtcDateTime } catch { return $null }
}

$idsSet = @{}; foreach ($z in $ids) { $idsSet[[string]$z] = $true }  # “in current WIQL delta” set

# If we’re in FULL scope (i.e., no WIQL delta), push everything to keep DB fields (like state) fresh.
if ($src -eq 'full') {
  $exactDelta = $tickets
} else {
  $exactDelta = $tickets | Where-Object {
    $idStr = [string]$_.id
    $isMissing = $false
    if ($missingIds -and $missingIds.Count -gt 0) { $isMissing = ($missingIds -contains $idStr) }

    $md = $null; $cd = $null
    try { $md = [datetime]$_.changedDate } catch { $md = $null }
    try { $cd = [datetime]$_.createdDate } catch { $cd = $null }
    $eff = if ($md) { $md } elseif ($cd) { $cd } else { $null }

    # Use >= to avoid boundary losses
    $isMissing -or ($eff -and $eff.ToUniversalTime() -ge $EffSinceUtc)
  }
}





# ---------- Push to Public API ----------
$pushUrl = "$PublicApiBase/api/sync/tickets"
$headers = @{ 'x-api-key' = $PublicApiKey; 'Content-Type' = 'application/json; charset=utf-8' }
$pushBatchSize = 200

function ToIso([object]$v) {
  if (-not $v) { return $null }
  try { return (Get-Date $v).ToUniversalTime().ToString("o") } catch { return $null }
}


for ($i = 0; $i -lt $exactDelta.Count; $i += $pushBatchSize) {
  $end   = [Math]::Min($i + $pushBatchSize - 1, $exactDelta.Count - 1)
  $chunk = $exactDelta[$i..$end]

  $payloadTickets += [PSCustomObject]@{
  id                 = [string]$t.id
  type               = Sanitize $t.type
  title              = Sanitize $t.title
  state              = Sanitize $t.state
  reason             = Sanitize $t.reason
  priority           = $t.priority
  severity           = Sanitize $t.severity
  assignedTo         = Sanitize $t.assignedTo
  areaPath           = Sanitize $t.areaPath
  iterationPath      = Sanitize $t.iterationPath
  createdDate        = ToIso $t.createdDate
  changedDate        = ToIso $t.changedDate
  stateChangeDate    = ToIso $t.stateChangeDate
  tags               = Sanitize $t.tags
  foundInBuild       = Sanitize $t.foundInBuild
  integratedInBuild  = Sanitize $t.integratedInBuild
  relatedLinkCount   = $t.relatedLinkCount
  effort             = $t.effort
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




# ---- Presence sweep: tell the API what is currently in-scope so it can tombstone the rest
try {
  $presenceUrl = "$PublicApiBase/api/sync/tickets"
  $presenceObj = @{
    source            = 'tfs-agent'
    tickets           = @()  # no upserts in this call
    pushedAt          = (Get-Date).ToUniversalTime().ToString('o')
    presentIds        = ($idsFull | ForEach-Object { [string]$_ })   # <<< use FULL scope here
    presentIteration  = $currentIterName                              # e.g., "Sprint 2025-400"
    presentIterationPath  = $currentIterPath   # <<< NEW
  }
  $presenceJson  = $presenceObj | ConvertTo-Json -Depth 6
  $presenceBytes = [Text.Encoding]::UTF8.GetBytes($presenceJson)
  Write-Log "Posting presence list ($($idsFull.Count) ids) to $presenceUrl ..."
  $null = Invoke-RestMethod -Method Post -Uri $presenceUrl `
           -Headers @{ 'x-api-key' = $PublicApiKey; 'Content-Type' = 'application/json; charset=utf-8' } `
           -Body $presenceBytes
  Write-Log "Presence sweep: OK"
} catch {
  Write-Warning "Presence sweep failed: $($_.Exception.Message)"
}


# ---------- Advance watermark ----------
$maxEffUtc = $null
foreach ($it in $tickets) {
  $md = $null; $cd = $null
  try { $md = ([datetime]$it.changedDate).ToUniversalTime() } catch { $md = $null }
  try { $cd = ([datetime]$it.createdDate).ToUniversalTime() } catch { $cd = $null }
  $eff = if ($md) { $md } elseif ($cd) { $cd } else { $null }
  if ($eff -and (-not $maxEffUtc -or $eff -gt $maxEffUtc)) { $maxEffUtc = $eff }
}

if ($maxEffUtc) {
  $safeMark = $maxEffUtc.AddMinutes(-2)
  if ($safeMark -lt $SinceUtc) { $safeMark = $SinceUtc }
  if ($safeMark -gt $NowUtc) { $safeMark = $NowUtc }

  Save-LastSyncUtc $safeMark
  Write-Log "[delta] advanced LastSyncUtc - $($safeMark.ToString('o')) (from newest Changed/Created)"
} else {
  # No items came back — keep the previous watermark to avoid missing near-boundary creations
  Write-Log "[delta] no items changed; watermark UNCHANGED ($($SinceUtc.ToString('o')))"
}

