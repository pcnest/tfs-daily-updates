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
$Pat           = "x34cxkcnvd7zuxw6egqyg2yyf6frsbw3vjjnmh37xgar2aopxwqa"                # Read-only PAT is recommended
$WiqlFile      = ".\sample.wiql"               # WIQL file path (relative to this script)
$PublicApiBase = "https://tfs-daily-api.onrender.com"  # e.g., https://your-host/api
$PublicApiKey  = "3bded27a3b75ee54e2ae2da4293687c26172d3f551e3584e343c71d399e4054f"           # Must match API_KEY in the server's .env
# --------------------------------------------

# ---------- Delta Sync ----------
$AgentDir    = Split-Path -Parent $MyInvocation.MyCommand.Path
$SyncFile    = Join-Path $AgentDir "last_sync.json"
$InitialDays = 14   # initial backfill window
$OverlapMins = 5    # safety overlap to avoid gaps
$NowUtc      = (Get-Date).ToUniversalTime()


# Helpers
Function Write-Log($msg) {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$ts] $msg"
}
Function Sanitize([object]$v) {
    if ($null -eq $v) { return "" }
    $s = [string]$v
    # Replace ASCII control chars, Unicode line/paragraph separators, and stray surrogates
    $s = $s -replace '[\u0000-\u001F\u2028\u2029]', ' '
    $s = $s -replace '[\uD800-\uDFFF]', ' '   # remove unpaired surrogate code points
    # Trim and collapse excessive whitespace
    $s = $s.Trim()
    $s = $s -replace '\s{2,}', ' '
    return $s
}

# delta-sync helpers
function Get-LastSyncUtc {
  if (Test-Path $SyncFile) {
    try {
      $js = Get-Content $SyncFile -Raw | ConvertFrom-Json
      if ($js.lastSyncUtc) { return [datetime]::Parse($js.lastSyncUtc) }
    } catch {}
  }
  return $NowUtc.AddDays(-$InitialDays)
}
function Save-LastSyncUtc([datetime]$whenUtc) {
  @{ lastSyncUtc = $whenUtc.ToString('o') } | ConvertTo-Json | Out-File -Encoding UTF8 $SyncFile
}

$SinceUtc       = Get-LastSyncUtc
$SinceDateOnly  = $SinceUtc.ToString('yyyy-MM-dd')    # TFS 2017 WIQL expects DATE (no time)
Write-Log "[delta] LastSync (date-only): $SinceDateOnly"





# Prepare headers for TFS (Basic auth using PAT)
$pair = ":" + $Pat
$bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
$base64 = [System.Convert]::ToBase64String($bytes)
$tfsHeaders = @{
    Authorization = "Basic $base64"
    "Content-Type" = "application/json"
}

# Read WIQL query + inject delta filter
if (!(Test-Path $WiqlFile)) {
    Write-Error "WIQL file not found: $WiqlFile"
    exit 1
}
$wiqlRaw = Get-Content $WiqlFile -Raw

# Accept either JSON {"query":"..."} or plain WIQL text
$q = $null
try {
    $maybeJson = $wiqlRaw | ConvertFrom-Json
    if ($maybeJson.query) { $q = [string]$maybeJson.query }
} catch { }
if (-not $q) { $q = [string]$wiqlRaw }

# Build delta clause (date-only)
$deltaClause = "[System.ChangedDate] >= '$SinceDateOnly'"

# Insert delta BEFORE ORDER BY (if present), otherwise append both WHERE/AND + ORDER BY.
$hasWhere = [regex]::IsMatch($q, '\bWHERE\b', 'IgnoreCase')
$matchOB  = [regex]::Match($q, '\bORDER\s+BY\b', 'IgnoreCase')

if ($matchOB.Success) {
    $head = $q.Substring(0, $matchOB.Index).TrimEnd()
    $tail = $q.Substring($matchOB.Index)  # "ORDER BY ..."
    if ($hasWhere) { $head = "$head`n  AND $deltaClause" } else { $head = "$head`nWHERE $deltaClause" }
    $q = "$head`n$tail"
} else {
    if ($hasWhere) { $q = "$q`n  AND $deltaClause" } else { $q = "$q`nWHERE $deltaClause" }
    $q = "$q`nORDER BY [System.ChangedDate] DESC"
}

$wiqlBody = @{ query = $q } | ConvertTo-Json -Depth 3

# (Optional) debug: see exact WIQL sent
# Write-Log ("--- WIQL ---`n{0}`n-----------" -f $q)

# Team/project WIQL URL (unchanged)
if ($Team -and $Team.Trim().Length -gt 0) {
    $wiqlUrl = "$TfsUrl/$Collection/$Project/$Team/_apis/wit/wiql?api-version=2.0"
} else {
    $wiqlUrl = "$TfsUrl/$Collection/$Project/_apis/wit/wiql?api-version=2.0"
}

# (Optional) log current iteration (unchanged)
try {
    if ($Team -and $Team.Trim().Length -gt 0) {
        $iterUrl = "$TfsUrl/$Collection/$Project/$Team/_apis/work/teamsettings/iterations?`$timeframe=current&api-version=2.0"
        $iterResp = Invoke-RestMethod -Method Get -Uri $iterUrl -Headers $tfsHeaders
        if ($iterResp.value -and $iterResp.value.Count -gt 0) {
            $curr = $iterResp.value[0]
            Write-Log "Team '$Team' current iteration: $($curr.name) ($($curr.attributes.startDate) → $($curr.attributes.endDate))"
        } else {
            Write-Log "Team '$Team' current iteration: NONE (check team settings)"
        }
    }
} catch { Write-Log "Warning: Could not fetch team current iteration. $_" }

Write-Log "Posting WIQL (delta since $SinceDateOnly) to $wiqlUrl ..."
$wiqlResponse = Invoke-RestMethod -Method Post -Uri $wiqlUrl -Headers $tfsHeaders -Body $wiqlBody -ContentType 'application/json'
$ids = $wiqlResponse.workItems | ForEach-Object { $_.id } | Select-Object -Unique

if (!$ids -or $ids.Count -eq 0) {
    Write-Log "No work items returned by WIQL (delta)."
    $ids = @()
} else {
    Write-Log "WIQL returned $($ids.Count) IDs (delta)"
}


# 2) GET details for those IDs in batches
Function Get-WorkItems($idBatch) {
    if (!$idBatch -or $idBatch.Count -eq 0) { return @() }
    $idList = ($idBatch -join ",")
    $fields = @(
        "System.Id",
        "System.WorkItemType",
        "System.Title",
        "System.State",
        "System.AssignedTo",
        "System.AreaPath",
        "System.IterationPath",
        "System.ChangedDate",
        "System.Tags"
    ) -join ","
    $url = "$TfsUrl/$Collection/_apis/wit/workitems?ids=$idList&fields=$fields&api-version=2.0"
    Write-Log "Fetching details for IDs: $idList"
    $resp = Invoke-RestMethod -Method Get -Uri $url -Headers $tfsHeaders
    return $resp.value
}

$tickets = @()
$batchSize = 180
for ($i = 0; $i -lt $ids.Count; $i += $batchSize) {
    $batch = $ids[$i..([Math]::Min($i+$batchSize-1, $ids.Count-1))]
    $items = Get-WorkItems $batch
    foreach ($it in $items) {
        $f = $it.fields        
        $assigned = ""
        $ass = $f.'System.AssignedTo'
        if ($null -ne $ass) {
            if ($ass -is [string]) {
                $assigned = $ass
            } elseif ($ass -is [hashtable]) {
                if ($ass['uniqueName'])      { $assigned = [string]$ass['uniqueName'] }
                elseif ($ass['displayName']) { $assigned = [string]$ass['displayName'] }
                elseif ($ass['name'])        { $assigned = [string]$ass['name'] }
            } else {
                # PSCustomObject case
                if ($ass.PSObject.Properties['uniqueName'])      { $assigned = [string]$ass.uniqueName }
                elseif ($ass.PSObject.Properties['displayName']) { $assigned = [string]$ass.displayName }
                elseif ($ass.PSObject.Properties['name'])        { $assigned = [string]$ass.name }
                else { $assigned = [string]$ass }
            }
        }
        $assigned = Sanitize $assigned
                $tickets += [PSCustomObject]@{
            id            = $f."System.Id"
            type          = $f."System.WorkItemType"
            title         = $f."System.Title"
            state         = $f."System.State"
            assignedTo    = $assigned
            areaPath      = $f."System.AreaPath"
            iterationPath = $f."System.IterationPath"
            changedDate   = $f."System.ChangedDate"
            tags          = $f."System.Tags"
        }
    }
    $types = $tickets | Select-Object -ExpandProperty type -Unique
Write-Log ("Types seen: " + ($types -join ", "))

}

# 3) Push to Public API in chunks (sanitized, UTF-8 bytes)
$pushUrl = "$PublicApiBase/api/sync/tickets"
$headers = @{
    "x-api-key"    = $PublicApiKey
    "Content-Type" = "application/json; charset=utf-8"
}
$pushBatchSize = 200   # smaller helps isolate bad records

for ($i = 0; $i -lt $tickets.Count; $i += $pushBatchSize) {
    $end   = [Math]::Min($i + $pushBatchSize - 1, $tickets.Count - 1)
    $chunk = $tickets[$i..$end]

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
            changedDate   = (Get-Date $t.changedDate).ToString("o")
            tags          = Sanitize $t.tags
        }
    }

    $obj = @{
        source   = "tfs-agent"
        tickets  = $payloadTickets
        pushedAt = (Get-Date).ToString("o")
    }

    # Convert to JSON, then force UTF-8 bytes to avoid encoding ambiguity
    $json  = $obj | ConvertTo-Json -Depth 8
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)

    Write-Log "Pushing tickets $i..$end ($($payloadTickets.Count)) to $pushUrl ..."
    try {
        $result = Invoke-RestMethod -Method Post -Uri $pushUrl -Headers $headers -Body $bytes
        Write-Log "Chunk push result: $($result.status); count=$($result.count)"
    } catch {
        Write-Error $_.Exception.Message
        if ($_.Exception.Response) {
            $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd()
            Write-Error "Server said: $responseBody"
        }
        # Optional: write the problematic payload for inspection
        $dumpFile = "payload-failed-$i-$end.json"
        [IO.File]::WriteAllBytes($dumpFile, $bytes)
        Write-Error "Saved failing payload to $dumpFile"
        exit 1
    }
}
Write-Log "All chunks pushed. Total tickets: $($tickets.Count)"

# advance delta marker (with small overlap)
$NewMarker = $NowUtc.AddMinutes(-$OverlapMins)
Save-LastSyncUtc $NewMarker
Write-Log "[delta] advanced LastSyncUtc to $($NewMarker.ToString('o'))"





