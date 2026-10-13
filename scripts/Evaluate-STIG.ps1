# REF-Eval-STIG.ps1 - evaluates a DISA STIG SCAP benchmark on this machine in pure PowerShell.
#
# WHY. DISA's scanner (SCC) ships about a hundred unsigned runtime DLLs; App Control blocks them
# (27 May, 2 Oct and 5 Oct 2026), and allowing them one by one is not a dependable route. The
# benchmark itself is data: XCCDF rules that point at OVAL definitions. This script reads DISA's
# published benchmark file unchanged and evaluates those OVAL definitions itself - the same checks,
# no third-party binaries. PowerShell scripts are not subject to the App Control block.
#
# READ-ONLY. It reads the registry, audit policy (auditpol /get), user rights and account policy
# (secedit /export to a temp file that is deleted), WMI, local accounts and file ACLs. It changes
# nothing. Results go to Evidence\<date>\stig-eval-<machine>\.
#
# It is NOT SCC. The result is "DISA benchmark content evaluated by REF-Eval-STIG.ps1", and
# every rule result is listed with what was found so it can be checked by hand.
#
# Usage, elevated window:
#   & ([scriptblock]::Create((Get-Content '<this file>' -Raw))) -Machine WS01
# Unelevated it refuses, unless -AllowPartial is given (rules that need elevation then report 'error').

param(
    [Parameter(Mandatory)] [ValidateSet('WS01', 'WS02')] [string]$Machine,
    [string]$Benchmark = 'C:\Users\SecurityOfficer\OneDrive - Sanctir\02 Compliance & IT\Compliance Library\DISA-STIG\Windows_11_V2R8\U_MS_Windows_11_V2R8_STIG_SCAP_1-3_Benchmark.xml',
    [string]$ProfileId = 'MAC-2_Sensitive',
    [string]$EvidenceRoot = (Join-Path (Split-Path -Parent $PSScriptRoot) 'Evidence'),
    [switch]$AllowPartial,
    [switch]$NoFiles
)
$ErrorActionPreference = 'Stop'
if ($env:COMPUTERNAME -ne $Machine) { throw "This is ${env:COMPUTERNAME}, not $Machine. Nothing run." }
$script:Elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $script:Elevated -and -not $AllowPartial) { throw 'Not elevated. Open the elevated window (REF-la) and run again, or pass -AllowPartial for a partial result. Nothing run.' }
if (-not (Test-Path $Benchmark)) { throw "Benchmark not found: $Benchmark" }
if ($Benchmark -match 'enhanced') { throw 'That is not the DISA-published benchmark file.' }

# ---------- load the benchmark ----------
if ($Benchmark -match '\.zip$') {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead($Benchmark)
    try { $entry = $zip.Entries | Where-Object { $_.Name -match 'Benchmark\.xml$' } | Select-Object -First 1; $sr = New-Object IO.StreamReader($entry.Open()); $raw = $sr.ReadToEnd(); $sr.Dispose() } finally { $zip.Dispose() }
} else { $raw = Get-Content $Benchmark -Raw }
$doc = New-Object Xml.XmlDocument; $doc.PreserveWhitespace = $false; $doc.LoadXml($raw)
$nsm = New-Object Xml.XmlNamespaceManager $doc.NameTable
$nsm.AddNamespace('x', 'http://checklists.nist.gov/xccdf/1.2'); $nsm.AddNamespace('o', 'http://oval.mitre.org/XMLSchema/oval-definitions-5')
$bench = $doc.SelectNodes('//x:Benchmark', $nsm)[0]
$rules = @($bench.SelectNodes('.//x:Rule', $nsm))
$firstDef = $rules[0].SelectSingleNode('x:check/x:check-content-ref', $nsm).GetAttribute('name')
$oval = $null
foreach ($od in $doc.SelectNodes('//o:oval_definitions', $nsm)) { if ($od.SelectSingleNode("o:definitions/o:definition[@id='$firstDef']", $nsm)) { $oval = $od; break } }
if (-not $oval) { throw 'Could not find the OVAL component the rules refer to.' }
function ElementKids($n) { @($n.ChildNodes | Where-Object { $_.NodeType -eq 'Element' }) }
$Defs = @{}; $Tests = @{}; $Objs = @{}; $States = @{}; $Vars = @{}
# Load every OVAL component: the checks, and the CPE-OVAL that decides rule applicability.
foreach ($od in $doc.SelectNodes('//o:oval_definitions', $nsm)) {
    foreach ($pair in @(@('definitions', $Defs), @('tests', $Tests), @('objects', $Objs), @('states', $States), @('variables', $Vars))) {
        $sec = $od.SelectSingleNode("o:$($pair[0])", $nsm)
        if ($sec) { foreach ($n in (ElementKids $sec)) { if (-not $pair[1].ContainsKey($n.GetAttribute('id'))) { $pair[1][$n.GetAttribute('id')] = $n } } }
    }
}
# Applicability (XCCDF <platform>): platform id -> CPE logical test; CPE name -> OVAL definition.
$Platforms = @{}; foreach ($p in $doc.SelectNodes('//*[local-name()="platform-specification"]/*[local-name()="platform"]')) { $Platforms[$p.GetAttribute('id')] = $p }
$CpeChecks = @{}; foreach ($ci in $doc.SelectNodes('//*[local-name()="cpe-item"]')) { $chk = $ci.SelectSingleNode('*[local-name()="check"]'); if ($chk) { $CpeChecks[$ci.GetAttribute('name')] = $chk.InnerText.Trim() } }
function AttrOr($node, $name, $default) { if ($node -and $node.HasAttribute($name)) { $node.GetAttribute($name) } else { $default } }
function Kid($node, $localName) { foreach ($c in $node.ChildNodes) { if ($c.NodeType -eq 'Element' -and $c.LocalName -eq $localName) { return $c } }; return $null }

# ---------- comparison ----------
function ConvertTo-OvalBool($v) { return ("$v".Trim().ToLower() -in 'true', '1') }
function Compare-OvalVersion($a, $b) {
    $pa = @("$a" -split '[^0-9]+' | Where-Object { $_ -ne '' }); $pb = @("$b" -split '[^0-9]+' | Where-Object { $_ -ne '' })
    for ($i = 0; $i -lt [Math]::Max($pa.Count, $pb.Count); $i++) {
        $x = if ($i -lt $pa.Count) { [long]$pa[$i] } else { 0 }; $y = if ($i -lt $pb.Count) { [long]$pb[$i] } else { 0 }
        if ($x -ne $y) { return [Math]::Sign($x - $y) }
    }
    return 0
}
function Compare-OvalOne($actual, $expected, $datatype, $operation) {
    switch ($datatype) {
        'int' {
            $a = 0L; $e = 0L
            if (-not [long]::TryParse("$actual".Trim(), [ref]$a)) { return $false }
            if (-not [long]::TryParse("$expected".Trim(), [ref]$e)) { throw "expected value '$expected' is not an integer" }
            switch ($operation) { 'equals' { return $a -eq $e } 'not equal' { return $a -ne $e } 'greater than' { return $a -gt $e } 'less than' { return $a -lt $e } 'greater than or equal' { return $a -ge $e } 'less than or equal' { return $a -le $e } 'bitwise and' { return (($a -band $e) -eq $e) } 'bitwise or' { return (($a -bor $e) -eq $e) } default { throw "int operation '$operation' not supported" } }
        }
        'boolean' {
            $a = ConvertTo-OvalBool $actual; $e = ConvertTo-OvalBool $expected
            switch ($operation) { 'equals' { return $a -eq $e } 'not equal' { return $a -ne $e } default { throw "boolean operation '$operation' not supported" } }
        }
        'version' {
            $c = Compare-OvalVersion $actual $expected
            switch ($operation) { 'equals' { return $c -eq 0 } 'not equal' { return $c -ne 0 } 'greater than' { return $c -gt 0 } 'less than' { return $c -lt 0 } 'greater than or equal' { return $c -ge 0 } 'less than or equal' { return $c -le 0 } default { throw "version operation '$operation' not supported" } }
        }
        default {
            $a = "$actual"; $e = "$expected"
            switch ($operation) {
                'equals' { return [string]::Equals($a, $e, [StringComparison]::Ordinal) }
                'not equal' { return -not [string]::Equals($a, $e, [StringComparison]::Ordinal) }
                'case insensitive equals' { return [string]::Equals($a, $e, [StringComparison]::OrdinalIgnoreCase) }
                'case insensitive not equal' { return -not [string]::Equals($a, $e, [StringComparison]::OrdinalIgnoreCase) }
                'pattern match' { return [regex]::IsMatch($a, $e) }
                default { throw "string operation '$operation' not supported" }
            }
        }
    }
}
function Join-Check($bools, $mode) {
    $arr = @($bools); $t = @($arr | Where-Object { $_ }).Count
    switch ($mode) { 'all' { return ($arr.Count -gt 0 -and $t -eq $arr.Count) } 'at least one' { return $t -ge 1 } 'none satisfy' { return $t -eq 0 } 'only one' { return $t -eq 1 } default { throw "check '$mode' not supported" } }
}
# Does the item's field (an array of values) satisfy this state entity?
function Test-OvalEntity($values, $entity) {
    if ($null -eq $values) { return $false }
    $datatype = AttrOr $entity 'datatype' 'string'; $operation = AttrOr $entity 'operation' 'equals'
    $entityCheck = AttrOr $entity 'entity_check' 'all'; $varCheck = AttrOr $entity 'var_check' 'all'
    $expected = if ($entity.HasAttribute('var_ref')) { @(Resolve-OvalVar $entity.GetAttribute('var_ref')) } else { @($entity.InnerText) }
    $perValue = foreach ($v in @($values)) { Join-Check @(foreach ($e in $expected) { Compare-OvalOne $v $e $datatype $operation }) $varCheck }
    return (Join-Check @($perValue) $entityCheck)
}
function Test-OvalItemState($item, $stateId) {
    $state = $States[$stateId]; if (-not $state) { throw "state $stateId not found" }
    $results = foreach ($ent in (ElementKids $state)) {
        if ($ent.LocalName -eq 'result') {   # WMI record
            $rec = $item['result']
            $fieldResults = foreach ($f in (ElementKids $ent)) { $fname = $f.GetAttribute('name').ToLower(); if ($rec -and $rec.ContainsKey($fname)) { Test-OvalEntity $rec[$fname] $f } else { $false } }
            (@($fieldResults | Where-Object { -not $_ }).Count -eq 0)
        } else { Test-OvalEntity $item[$ent.LocalName] $ent }
    }
    return (@($results | Where-Object { -not $_ }).Count -eq 0)
}

# ---------- variables ----------
$script:VarCache = @{}
function Get-OvalComponentValues($comp) {
    switch ($comp.LocalName) {
        'literal_component' { return , @($comp.InnerText) }
        'object_component' {
            $col = Get-OvalItems $comp.GetAttribute('object_ref'); if ($col.Error) { throw "variable source: $($col.Error)" }
            $field = $comp.GetAttribute('item_field'); $vals = New-Object Collections.ArrayList
            foreach ($it in $col.Items) { if ($it['_exists'] -ne $false -and $null -ne $it[$field]) { foreach ($v in @($it[$field])) { [void]$vals.Add("$v") } } }
            return , @($vals)
        }
        'regex_capture' {
            $pattern = $comp.GetAttribute('pattern'); $inner = Get-OvalComponentValues @(ElementKids $comp)[0]
            return , @(foreach ($v in $inner) { $m = [regex]::Match($v, $pattern); if ($m.Success -and $m.Groups.Count -gt 1) { $m.Groups[1].Value } else { '' } })
        }
        'concat' {
            $acc = @('')
            foreach ($child in (ElementKids $comp)) { $vals = Get-OvalComponentValues $child; $acc = @(foreach ($a in $acc) { foreach ($v in $vals) { "$a$v" } }) }
            return , @($acc)
        }
        default { throw "variable component '$($comp.LocalName)' not supported" }
    }
}
function Resolve-OvalVar($id) {
    if (-not $script:VarCache.ContainsKey($id)) { $v = $Vars[$id]; if (-not $v) { throw "variable $id not found" }; $script:VarCache[$id] = @(Get-OvalComponentValues @(ElementKids $v)[0]) }
    return $script:VarCache[$id]
}

# ---------- collectors ----------
function New-Item2($id, $show) { $h = @{}; $h['_id'] = $id; $h['_exists'] = $true; $h['_show'] = $show; return $h }
function ConvertTo-RegItem($hiveName, $keyPath, $key, $name) {
    $kind = $key.GetValueKind($name); $raw = $key.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    $type = 'reg_none'; $vals = @("$raw")
    switch ($kind) {
        'DWord' { $type = 'reg_dword'; $vals = @(([long]$raw -band 0xFFFFFFFFL).ToString()) }
        'QWord' { $type = 'reg_qword'; $vals = @(([decimal]([uint64]([BitConverter]::ToUInt64([BitConverter]::GetBytes([long]$raw), 0)))).ToString()) }
        'String' { $type = 'reg_sz' }
        'ExpandString' { $type = 'reg_expand_sz' }
        'MultiString' { $type = 'reg_multi_sz'; $vals = @($raw); if ($vals.Count -eq 0) { $vals = @('') } }
        'Binary' { $type = 'reg_binary'; $vals = @((($raw | ForEach-Object { $_.ToString('X2') }) -join '')) }
    }
    $it = New-Item2 "$hiveName|$($keyPath.ToLower())|$("$name".ToLower())" "$keyPath\$name = $($vals -join ',') ($type)"
    $it['hive'] = @($hiveName); $it['key'] = @($keyPath); $it['name'] = @($name); $it['type'] = @($type); $it['value'] = $vals
    return $it
}
function Get-RegistryItems($obj) {
    $items = New-Object Collections.ArrayList
    $hiveName = (Kid $obj 'hive').InnerText; $keyNode = Kid $obj 'key'; $nameNode = Kid $obj 'name'; $beh = Kid $obj 'behaviors'
    $hive = if ($hiveName -eq 'HKEY_LOCAL_MACHINE') { [Microsoft.Win32.RegistryHive]::LocalMachine } elseif ($hiveName -eq 'HKEY_CURRENT_USER') { [Microsoft.Win32.RegistryHive]::CurrentUser } elseif ($hiveName -eq 'HKEY_USERS') { [Microsoft.Win32.RegistryHive]::Users } else { throw "hive $hiveName not supported" }
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, [Microsoft.Win32.RegistryView]::Registry64)
    try {
        $keyOp = AttrOr $keyNode 'operation' 'equals'; $keyPaths = New-Object Collections.ArrayList
        if ($keyOp -eq 'pattern match') {
            $pattern = $keyNode.InnerText
            $literal = [regex]::Match($pattern, '^(?:[^\\\.\[\]\(\)\*\+\?\^\$\{\}\|]|\\\\)*').Value      # leading literal part
            $prefix = ($literal -replace '\\\\', '\'); $cut = $prefix.LastIndexOf('\'); if ($cut -ge 0) { $prefix = $prefix.Substring(0, $cut) } else { $prefix = '' }
            $stack = New-Object Collections.Stack; $stack.Push(@($prefix, 0))
            while ($stack.Count) {
                $cur = $stack.Pop(); $k = $base.OpenSubKey($cur[0]); if (-not $k) { continue }
                try { if ($cur[0] -and [regex]::IsMatch($cur[0], $pattern, 'IgnoreCase')) { [void]$keyPaths.Add($cur[0]) }
                      if ($cur[1] -lt 4) { foreach ($s in $k.GetSubKeyNames()) { $stack.Push(@($(if ($cur[0]) { "$($cur[0])\$s" } else { $s }), ($cur[1] + 1))) } } } finally { $k.Close() }
            }
        } else {
            [void]$keyPaths.Add($keyNode.InnerText)
            if ($beh -and $beh.GetAttribute('recurse_direction') -eq 'down') {
                $k = $base.OpenSubKey($keyNode.InnerText); if ($k) { try { foreach ($s in $k.GetSubKeyNames()) { [void]$keyPaths.Add("$($keyNode.InnerText)\$s") } } finally { $k.Close() } }
            }
        }
        $nameNil = ($nameNode -and $nameNode.GetAttribute('nil', 'http://www.w3.org/2001/XMLSchema-instance') -eq 'true')
        $nameOp = AttrOr $nameNode 'operation' 'equals'
        foreach ($kp in $keyPaths) {
            $k = $base.OpenSubKey($kp); if (-not $k) { continue }
            try {
                if ($nameNil) { $it = New-Item2 "$hiveName|$($kp.ToLower())|" "$kp (key exists)"; $it['hive'] = @($hiveName); $it['key'] = @($kp); [void]$items.Add($it); continue }
                $valueNames = @($k.GetValueNames())
                if ($nameOp -eq 'pattern match') { foreach ($vn in $valueNames) { if ([regex]::IsMatch($vn, $nameNode.InnerText, 'IgnoreCase')) { [void]$items.Add((ConvertTo-RegItem $hiveName $kp $k $vn)) } } }
                else { $vn = $valueNames | Where-Object { $_ -ieq $nameNode.InnerText } | Select-Object -First 1; if ($null -ne $vn) { [void]$items.Add((ConvertTo-RegItem $hiveName $kp $k $vn)) } }
            } finally { $k.Close() }
        }
    } finally { $base.Close() }
    return $items
}
function Get-NtuserItems($obj) {
    $items = New-Object Collections.ArrayList
    $keyPath = (Kid $obj 'key').InnerText; $name = (Kid $obj 'name').InnerText
    $plist = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' | Where-Object { $_.PSChildName -match '^S-1-(5-21|12-1)-' }
    $users = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::Users, [Microsoft.Win32.RegistryView]::Registry64)
    try {
        foreach ($p in $plist) {
            $sid = $p.PSChildName; $path = (Get-ItemProperty $p.PSPath).ProfileImagePath; $dat = Join-Path $path 'NTUSER.DAT'
            $enabled = $true; try { $lu = Get-LocalUser -SID $sid -ErrorAction Stop; $enabled = [bool]$lu.Enabled } catch { }
            $days = 0; try { $days = [int]((Get-Date) - (Get-Item $dat -Force -ErrorAction Stop).LastWriteTime).TotalDays } catch { $days = 9999 }
            $it = New-Item2 "ntuser|$sid|$($keyPath.ToLower())|$($name.ToLower())" ''
            $it['sid'] = @($sid); $it['username'] = @(Split-Path $path -Leaf); $it['enabled'] = @("$enabled".ToLower()); $it['days_since_modified'] = @("$days"); $it['key'] = @($keyPath); $it['name'] = @($name)
            $hk = $users.OpenSubKey($sid); $mount = $sid; $loadedHere = $false
            # 10 Oct 2026: when elevated, an unloaded profile is loaded read-only for the check and unloaded again, so the result
            # no longer depends on which administrator runs the scan (6 Oct ran as REF-la, 10 Oct as admin).
            if (-not $hk -and $script:Elevated -and (Test-Path -LiteralPath $dat)) {
                $mount = "SANCTIR_EVAL_$($sid -replace '[^0-9]', '')"
                & reg.exe load "HKU\$mount" "$dat" 2>&1 | Out-Null
                if ($LASTEXITCODE -eq 0) { $loadedHere = $true; $hk = $users.OpenSubKey($mount) }
            }
            if (-not $hk) { $it['_exists'] = $false; $it['_unloaded'] = $true; $it['_show'] = "user $(Split-Path $path -Leaf): hive not loaded" }
            else {
                try {
                    $k = $hk.OpenSubKey($keyPath); $vn = $null
                    if ($k) { $vn = @($k.GetValueNames()) | Where-Object { $_ -ieq $name } | Select-Object -First 1 }
                    if ($null -ne $vn) { $ri = ConvertTo-RegItem 'HKEY_USERS' "$mount\$keyPath" $k $vn; $it['type'] = $ri['type']; $it['value'] = $ri['value']; $it['_show'] = "user $(Split-Path $path -Leaf): $keyPath\$name = $($ri['value'] -join ',')$(if ($loadedHere) { ' (profile loaded for the check)' })" }
                    else { $it['_exists'] = $false; $it['_show'] = "user $(Split-Path $path -Leaf): $keyPath\$name not set" }
                    if ($k) { $k.Close() }
                } finally { $hk.Close(); if ($loadedHere) { [GC]::Collect(); [GC]::WaitForPendingFinalizers(); & reg.exe unload "HKU\$mount" 2>&1 | Out-Null } }
            }
            [void]$items.Add($it)
        }
    } finally { $users.Close() }
    # Filters on the object (disabled accounts, stale profiles) are applied here.
    foreach ($f in @($obj.ChildNodes | Where-Object { $_.NodeType -eq 'Element' -and $_.LocalName -eq 'filter' })) {
        $action = AttrOr $f 'action' 'exclude'; $keep = New-Object Collections.ArrayList
        foreach ($it in $items) { $m = Test-OvalItemState $it $f.InnerText; if (($action -eq 'exclude' -and -not $m) -or ($action -eq 'include' -and $m)) { [void]$keep.Add($it) } }
        $items = $keep
    }
    $unloaded = @($items | Where-Object { $_['_unloaded'] })
    if ($unloaded.Count) { throw "profile hive not loaded for: $((($unloaded | ForEach-Object { $_['username'] }) -join ', ')) (sign that user in, then re-run)" }
    return $items
}
$script:AuditItem = $null
function Get-AuditItems {
    if (-not $script:AuditItem) {
        if (-not $script:Elevated) { throw 'audit policy needs elevation' }
        $csv = & auditpol.exe /get /category:* /r 2>&1; if ($LASTEXITCODE -ne 0) { throw "auditpol failed: $($csv -join ' ')" }
        $rows = $csv | Where-Object { $_ -and $_ -match ',' } | ConvertFrom-Csv
        $it = New-Item2 'auditpol' 'audit policy'
        foreach ($r in $rows) {
            $field = (($r.Subcategory.ToLower() -replace '[^a-z0-9]+', '_').Trim('_'))
            $val = switch ($r.'Inclusion Setting') { 'Success' { 'AUDIT_SUCCESS' } 'Failure' { 'AUDIT_FAILURE' } 'Success and Failure' { 'AUDIT_SUCCESS_FAILURE' } 'No Auditing' { 'AUDIT_NONE' } default { "UNKNOWN:$($r.'Inclusion Setting')" } }
            $it[$field] = @($val)
        }
        if ($it.ContainsKey('central_policy_staging')) { $it['central_access_policy_staging'] = $it['central_policy_staging'] }
        if ($it.ContainsKey('plug_and_play_events')) { $it['pnp_activity'] = $it['plug_and_play_events'] }
        $script:AuditItem = $it
    }
    $l = New-Object Collections.ArrayList; [void]$l.Add($script:AuditItem); return $l
}
$script:SecPol = $null
function Get-SecPol {
    if (-not $script:SecPol) {
        if (-not $script:Elevated) { throw 'user rights and account policy need elevation (secedit)' }
        $tmp = Join-Path $env:TEMP ("REF-secpol-{0}.inf" -f ([guid]::NewGuid().ToString('N')))
        try {
            $o = & secedit.exe /export /cfg $tmp /areas SECURITYPOLICY USER_RIGHTS 2>&1; if ($LASTEXITCODE -ne 0) { throw "secedit failed: $($o -join ' ')" }
            $sections = @{}; $cur = ''
            foreach ($line in (Get-Content $tmp)) { if ($line -match '^\[(.+)\]$') { $cur = $Matches[1]; $sections[$cur] = @{} } elseif ($line -match '^\s*([^=]+?)\s*=\s*(.*)$' -and $cur) { $sections[$cur][$Matches[1]] = $Matches[2].Trim() } }
            $script:SecPol = $sections
        } finally { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
    }
    return $script:SecPol
}
function ConvertTo-PrincipalName($entry) {
    $e = $entry.Trim(); $sidObj = $null
    try { if ($e.StartsWith('*')) { $sidObj = New-Object Security.Principal.SecurityIdentifier($e.Substring(1)) } else { $sidObj = (New-Object Security.Principal.NTAccount($e)).Translate([Security.Principal.SecurityIdentifier]) } } catch { return $e.TrimStart('*') }
    try { $nt = $sidObj.Translate([Security.Principal.NTAccount]).Value } catch { return $sidObj.Value }
    if ($nt -match '^(BUILTIN|NT AUTHORITY)\\(.+)$') { return $Matches[2] }
    return $nt
}
$script:TokenMap = $null; $script:AllRights = $null
function Get-TokenMap {
    if (-not $script:TokenMap) {
        $rights = (Get-SecPol)['Privilege Rights']; $map = @{}; $all = New-Object 'Collections.Generic.HashSet[string]' -ArgumentList ([StringComparer]::OrdinalIgnoreCase)
        foreach ($right in $rights.Keys) {
            [void]$all.Add($right.ToLower())
            foreach ($entry in ($rights[$right] -split ',')) { if (-not $entry.Trim()) { continue }; $p = ConvertTo-PrincipalName $entry; if (-not $map.ContainsKey($p)) { $map[$p] = New-Object 'Collections.Generic.HashSet[string]' -ArgumentList ([StringComparer]::OrdinalIgnoreCase) }; [void]$map[$p].Add($right.ToLower()) }
        }
        foreach ($st in $States.Values) { if ($st.LocalName -eq 'accesstoken_state') { foreach ($ent in (ElementKids $st)) { if ($ent.LocalName -ne 'security_principle') { [void]$all.Add($ent.LocalName) } } } }
        $script:TokenMap = $map; $script:AllRights = $all
    }
    return $script:TokenMap
}
function New-TokenItem($principal, $held) {
    $it = New-Item2 "token|$($principal.ToLower())" "$principal holds: $(if ($held -and $held.Count) { ($held | Sort-Object) -join ', ' } else { '(none)' })"
    $it['security_principle'] = @($principal); foreach ($r in $script:AllRights) { $it[$r] = @($(if ($held -and $held.Contains($r)) { '1' } else { '0' })) }
    return $it
}
function Get-AccessTokenItems($obj) {
    $items = New-Object Collections.ArrayList; $map = Get-TokenMap; $sp = Kid $obj 'security_principle'; $op = AttrOr $sp 'operation' 'equals'
    if ($op -eq 'pattern match') { foreach ($p in $map.Keys) { if ([regex]::IsMatch($p, $sp.InnerText)) { [void]$items.Add((New-TokenItem $p $map[$p])) } } }
    else {
        $hit = $map.Keys | Where-Object { $_ -ieq $sp.InnerText } | Select-Object -First 1
        if ($hit) { [void]$items.Add((New-TokenItem $hit $map[$hit])) }
        else { try { [void](New-Object Security.Principal.NTAccount($sp.InnerText)).Translate([Security.Principal.SecurityIdentifier]); [void]$items.Add((New-TokenItem $sp.InnerText $null)) } catch { } }
    }
    return $items
}
function Get-WmiItems($obj) {
    $items = New-Object Collections.ArrayList; $nsName = (Kid $obj 'namespace').InnerText; $wql = (Kid $obj 'wql').InnerText
    $rows = @(Get-CimInstance -Namespace $nsName -Query $wql -ErrorAction Stop); $i = 0
    foreach ($r in $rows) {
        $rec = @{}; foreach ($p in $r.CimInstanceProperties) { if ($null -ne $p.Value) { $rec[$p.Name.ToLower()] = @(@($p.Value) | ForEach-Object { "$_" }) } }
        $it = New-Item2 "wmi|$nsName|$wql|$i" (($rec.Keys | Sort-Object | ForEach-Object { "$_=$($rec[$_] -join ',')" }) -join '; '); $it['result'] = $rec; [void]$items.Add($it); $i++
    }
    return $items
}
function Get-FileRightsItems($obj) {
    $items = New-Object Collections.ArrayList; $fp = Kid $obj 'filepath'; if (-not $fp) { throw 'fileeffectiverights object without filepath is not supported' }
    $paths = if ($fp.HasAttribute('var_ref')) { @(Resolve-OvalVar $fp.GetAttribute('var_ref')) } else { @($fp.InnerText) }
    $sidPattern = (Kid $obj 'trustee_sid').InnerText
    foreach ($path in $paths) {
        $real = [Environment]::ExpandEnvironmentVariables($path); if (-not $real -or -not (Test-Path -LiteralPath $real)) { continue }
        $acl = Get-Acl -LiteralPath $real -ErrorAction Stop; $seen = @{}
        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            $sid = try { $ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { "$($ace.IdentityReference)" }
            if ($seen[$sid] -or -not [regex]::IsMatch($sid, $sidPattern)) { continue }; $seen[$sid] = $true
            $it = New-Item2 "file|$($real.ToLower())|$sid" "$real : $($ace.IdentityReference) ($sid) $($ace.FileSystemRights)"; $it['filepath'] = @($real); $it['trustee_sid'] = @($sid); [void]$items.Add($it)
        }
    }
    return $items
}
function Get-AccountPolicyItem($kind) {
    $sa = (Get-SecPol)['System Access']; function Num($k, $d) { if ($sa.ContainsKey($k)) { [long]$sa[$k] } else { $d } }
    if ($kind -eq 'password') {
        $it = New-Item2 'passwordpolicy' ''
        $max = Num 'MaximumPasswordAge' 0; $it['max_passwd_age'] = @($(if ($max -lt 0) { '4294967295' } else { "$($max * 86400)" }))
        $it['min_passwd_age'] = @("$((Num 'MinimumPasswordAge' 0) * 86400)"); $it['min_passwd_len'] = @("$(Num 'MinimumPasswordLength' 0)"); $it['password_hist_len'] = @("$(Num 'PasswordHistorySize' 0)")
        $it['password_complexity'] = @("$(Num 'PasswordComplexity' 0)"); $it['reversible_encryption'] = @("$(Num 'ClearTextPassword' 0)")
        $it['_show'] = "max age $max d; min age $(Num 'MinimumPasswordAge' 0) d; min length $(Num 'MinimumPasswordLength' 0); history $(Num 'PasswordHistorySize' 0); complexity $(Num 'PasswordComplexity' 0); reversible $(Num 'ClearTextPassword' 0)"
    } else {
        $it = New-Item2 'lockoutpolicy' ''
        $dur = Num 'LockoutDuration' 0; $it['lockout_duration'] = @($(if ($dur -lt 0) { '4294967295' } else { "$($dur * 60)" }))
        $it['lockout_observation_window'] = @("$((Num 'ResetLockoutCount' 0) * 60)"); $it['lockout_threshold'] = @("$(Num 'LockoutBadCount' 0)")
        $it['_show'] = "threshold $(Num 'LockoutBadCount' 0); duration $dur min; window $(Num 'ResetLockoutCount' 0) min"
    }
    $l = New-Object Collections.ArrayList; [void]$l.Add($it); return $l
}
function Get-SidItems($obj) {
    $items = New-Object Collections.ArrayList; $ts = Kid $obj 'trustee_sid'; $op = AttrOr $ts 'operation' 'equals'
    $cands = @(Get-LocalUser | ForEach-Object { @{ Sid = $_.SID.Value; Name = $_.Name } }) + @(Get-LocalGroup | ForEach-Object { @{ Sid = $_.SID.Value; Name = $_.Name } })
    foreach ($c in $cands) {
        $m = if ($op -eq 'pattern match') { [regex]::IsMatch($c.Sid, $ts.InnerText) } else { $c.Sid -eq $ts.InnerText }
        if ($m) { $it = New-Item2 "sid|$($c.Sid)" "$($c.Sid) is named '$($c.Name)'"; $it['trustee_sid'] = @($c.Sid); $it['trustee_name'] = @($c.Name); $it['trustee_domain'] = @($env:COMPUTERNAME); [void]$items.Add($it) }
    }
    return $items
}
function Get-UserSidItems($obj) {
    $items = New-Object Collections.ArrayList; $us = Kid $obj 'user_sid'
    $sids = if ($us.HasAttribute('var_ref')) { @(Resolve-OvalVar $us.GetAttribute('var_ref')) } else { @($us.InnerText) }
    foreach ($sid in $sids) { try { $u = Get-LocalUser -SID $sid -ErrorAction Stop; $it = New-Item2 "user|$sid" "account '$($u.Name)' enabled=$($u.Enabled)"; $it['user_sid'] = @($sid); $it['enabled'] = @("$([bool]$u.Enabled)".ToLower()); [void]$items.Add($it) } catch { } }
    return $items
}

$script:ObjCache = @{}
function Get-OvalItems($id) {
    if ($script:ObjCache.ContainsKey($id)) { return $script:ObjCache[$id] }
    $res = @{ Items = (New-Object Collections.ArrayList); Error = $null }
    try {
        $obj = $Objs[$id]; if (-not $obj) { throw "object $id not found" }
        $set = Kid $obj 'set'
        if ($set) {
            $operator = AttrOr $set 'set_operator' 'UNION'; $lists = New-Object Collections.ArrayList
            $filters = @($set.ChildNodes | Where-Object { $_.NodeType -eq 'Element' -and $_.LocalName -eq 'filter' })
            foreach ($ref in @($set.ChildNodes | Where-Object { $_.NodeType -eq 'Element' -and $_.LocalName -eq 'object_reference' })) {
                $sub = Get-OvalItems $ref.InnerText; if ($sub.Error) { throw $sub.Error }
                $kept = New-Object Collections.ArrayList
                foreach ($it in $sub.Items) {
                    $keep = $true
                    foreach ($f in $filters) { $m = Test-OvalItemState $it $f.InnerText; $action = AttrOr $f 'action' 'exclude'; if (($action -eq 'exclude' -and $m) -or ($action -eq 'include' -and -not $m)) { $keep = $false; break } }
                    if ($keep) { [void]$kept.Add($it) }
                }
                [void]$lists.Add($kept)
            }
            $seen = @{}
            switch ($operator) {
                'UNION' { foreach ($l in $lists) { foreach ($it in $l) { if (-not $seen[$it['_id']]) { $seen[$it['_id']] = $true; [void]$res.Items.Add($it) } } } }
                'INTERSECTION' { $ids2 = @{}; foreach ($it in $lists[1]) { $ids2[$it['_id']] = $true }; foreach ($it in $lists[0]) { if ($ids2[$it['_id']]) { [void]$res.Items.Add($it) } } }
                'COMPLEMENT' { $ids2 = @{}; foreach ($it in $lists[1]) { $ids2[$it['_id']] = $true }; foreach ($it in $lists[0]) { if (-not $ids2[$it['_id']]) { [void]$res.Items.Add($it) } } }
                default { throw "set operator $operator not supported" }
            }
        } else {
            $got = switch ($obj.LocalName) {
                'registry_object' { , (Get-RegistryItems $obj) }
                'ntuser_object' { , (Get-NtuserItems $obj) }
                'auditeventpolicysubcategories_object' { , (Get-AuditItems) }
                'accesstoken_object' { , (Get-AccessTokenItems $obj) }
                'wmi57_object' { , (Get-WmiItems $obj) }
                'fileeffectiverights53_object' { , (Get-FileRightsItems $obj) }
                'passwordpolicy_object' { , (Get-AccountPolicyItem 'password') }
                'lockoutpolicy_object' { , (Get-AccountPolicyItem 'lockout') }
                'sid_sid_object' { , (Get-SidItems $obj) }
                'user_sid55_object' { , (Get-UserSidItems $obj) }
                default { throw "object type $($obj.LocalName) not supported" }
            }
            foreach ($it in @($got)) { if ($it -is [hashtable]) { [void]$res.Items.Add($it) } elseif ($it) { foreach ($x in $it) { [void]$res.Items.Add($x) } } }
        }
    } catch { $res.Error = $_.Exception.Message }
    $script:ObjCache[$id] = $res; return $res
}

# ---------- tests and definitions ----------
$script:TestCache = @{}
function Get-OvalTestResult($id) {
    if ($script:TestCache.ContainsKey($id)) { return $script:TestCache[$id] }
    $t = $Tests[$id]; $out = @{ Result = 'error'; Found = ''; Comment = (AttrOr $t 'comment' '') }
    try {
        if (-not $t) { throw "test $id not found" }
        $exist = AttrOr $t 'check_existence' 'at_least_one_exists'; $check = AttrOr $t 'check' 'all'; $sop = AttrOr $t 'state_operator' 'AND'
        $col = Get-OvalItems (Kid $t 'object').GetAttribute('object_ref'); if ($col.Error) { throw $col.Error }
        $all = @($col.Items); $present = @($all | Where-Object { $_['_exists'] -ne $false }); $n = $present.Count
        $existsOk = switch ($exist) { 'all_exist' { $all.Count -gt 0 -and $n -eq $all.Count } 'any_exist' { $true } 'at_least_one_exists' { $n -ge 1 } 'none_exist' { $n -eq 0 } 'only_one_exists' { $n -eq 1 } default { throw "check_existence $exist not supported" } }
        $stateIds = @($t.ChildNodes | Where-Object { $_.NodeType -eq 'Element' -and $_.LocalName -eq 'state' } | ForEach-Object { $_.GetAttribute('state_ref') })
        $out.Found = if ($all.Count) { (($all | Select-Object -First 4 | ForEach-Object { $_['_show'] }) -join ' || ') + $(if ($all.Count -gt 4) { " (+$($all.Count - 4) more)" }) } else { 'nothing found (value or object not present)' }
        if (-not $existsOk) { $out.Result = 'false' }
        elseif ($stateIds.Count -eq 0 -or $n -eq 0) { $out.Result = 'true' }
        else {
            $perItem = foreach ($it in $present) { $sr = @(foreach ($sid in $stateIds) { Test-OvalItemState $it $sid }); if ($sop -eq 'OR') { (@($sr | Where-Object { $_ }).Count -ge 1) } else { (@($sr | Where-Object { -not $_ }).Count -eq 0) } }
            $out.Result = if (Join-Check @($perItem) $check) { 'true' } else { 'false' }
        }
    } catch { $out.Result = 'error'; $out.Found = "could not be read: $($_.Exception.Message)" }
    $script:TestCache[$id] = $out; return $out
}
function Join-OvalResults($results, $operator) {
    $r = @($results | Where-Object { $_ -ne 'not applicable' }); if ($r.Count -eq 0) { return 'not applicable' }
    $t = @($r | Where-Object { $_ -eq 'true' }).Count; $f = @($r | Where-Object { $_ -eq 'false' }).Count; $e = @($r | Where-Object { $_ -eq 'error' }).Count; $u = $r.Count - $t - $f - $e
    switch ($operator) {
        'AND' { if ($f) { 'false' } elseif ($e) { 'error' } elseif ($u) { 'unknown' } else { 'true' } }
        'OR' { if ($t) { 'true' } elseif ($e) { 'error' } elseif ($u) { 'unknown' } else { 'false' } }
        'ONE' { if ($t -eq 1 -and -not $e -and -not $u) { 'true' } elseif ($t -gt 1) { 'false' } elseif ($e) { 'error' } elseif ($u) { 'unknown' } else { 'false' } }
        default { throw "criteria operator $operator not supported" }
    }
}
function Invoke-Negate($r, $neg) { if ($neg -eq 'true') { if ($r -eq 'true') { 'false' } elseif ($r -eq 'false') { 'true' } else { $r } } else { $r } }
$script:DefCache = @{}; $script:DefStack = New-Object 'Collections.Generic.HashSet[string]' -ArgumentList ([StringComparer]::OrdinalIgnoreCase)
function Get-OvalCriteriaResult($node, $leaves) {
    $results = foreach ($c in (ElementKids $node)) {
        switch ($c.LocalName) {
            'criteria' { Invoke-Negate (Get-OvalCriteriaResult $c $leaves) (AttrOr $c 'negate' 'false') }
            'criterion' { $tr = Get-OvalTestResult $c.GetAttribute('test_ref'); $neg = AttrOr $c 'negate' 'false'; $r = Invoke-Negate $tr.Result $neg; [void]$leaves.Add(@{ Test = $c.GetAttribute('test_ref'); Obj = $(try { (Kid $Tests[$c.GetAttribute('test_ref')] 'object').GetAttribute('object_ref') } catch { '' }); Result = $r; Comment = $(if ($c.GetAttribute('comment')) { $c.GetAttribute('comment') } else { $tr.Comment }); Found = $tr.Found; Negated = ($neg -eq 'true') }); $r }
            'extend_definition' { Invoke-Negate (Get-OvalDefResult $c.GetAttribute('definition_ref') $leaves) (AttrOr $c 'negate' 'false') }
        }
    }
    return (Join-OvalResults @($results) (AttrOr $node 'operator' 'AND'))
}
function Get-OvalDefResult($id, $leaves) {
    if ($script:DefCache.ContainsKey($id) -and $null -eq $leaves) { return $script:DefCache[$id] }
    if (-not $script:DefStack.Add($id)) { throw "definition loop at $id" }
    try {
        $d = $Defs[$id]; if (-not $d) { throw "definition $id not found" }
        $crit = Kid $d 'criteria'; $mine = New-Object Collections.ArrayList
        $r = if ($crit) { Invoke-Negate (Get-OvalCriteriaResult $crit $mine) (AttrOr $crit 'negate' 'false') } else { 'not evaluated' }
        if ($null -ne $leaves) { foreach ($l in $mine) { [void]$leaves.Add($l) } }
        $script:DefCache[$id] = $r; return $r
    } finally { [void]$script:DefStack.Remove($id) }
}

# ---------- MDM cross-check (indicative, not part of DISA's logic) ----------
# Intune writes many settings to the MDM policy store rather than the Group Policy registry paths
# the benchmark reads. For each failing rule, list MDM-store values with the same value name.
$script:MdmIndex = @{}
foreach ($root in 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device') {
    if (-not (Test-Path $root)) { continue }
    foreach ($area in Get-ChildItem $root -ErrorAction SilentlyContinue) {
        $p = Get-ItemProperty $area.PSPath -ErrorAction SilentlyContinue; if (-not $p) { continue }
        foreach ($prop in $p.PSObject.Properties) {
            if ($prop.Name -match '^PS|_ProviderSet$|_WinningProvider$|_LastWrite$|_ADMXInstanceData$') { continue }
            $k = $prop.Name.ToLower(); if (-not $script:MdmIndex.ContainsKey($k)) { $script:MdmIndex[$k] = New-Object Collections.ArrayList }
            $v = "$($prop.Value)"; if ($v.Length -gt 60) { $v = $v.Substring(0, 60) + '…' }
            [void]$script:MdmIndex[$k].Add("$($area.PSChildName)/$($prop.Name)=$v")
        }
    }
}
function Get-MdmEquivalent($leaves) {
    $hits = New-Object Collections.ArrayList
    foreach ($l in @($leaves | Where-Object { $_.Result -ne 'true' })) {
        $o = if ($l.Obj) { $Objs[$l.Obj] } else { $null }; if (-not $o -or $o.LocalName -notin 'registry_object', 'ntuser_object') { continue }
        $n = Kid $o 'name'; if (-not $n -or -not $n.InnerText) { continue }
        $k = $n.InnerText.ToLower(); if ($script:MdmIndex.ContainsKey($k)) { foreach ($h in $script:MdmIndex[$k]) { if (-not $hits.Contains($h)) { [void]$hits.Add($h) } } }
    }
    return ($hits -join '; ')
}

# ---------- applicability ----------
function Test-CpeLogical($node) {
    $results = foreach ($c in (ElementKids $node)) {
        switch ($c.LocalName) {
            'logical-test' { Test-CpeLogical $c }
            'fact-ref' { $name = $c.GetAttribute('name'); if (-not $CpeChecks.ContainsKey($name)) { $true } else { (Get-OvalDefResult $CpeChecks[$name] $null) -eq 'true' } }
            'check-fact-ref' { (Get-OvalDefResult $c.GetAttribute('id-ref') $null) -eq 'true' }
        }
    }
    $arr = @($results); if ($arr.Count -eq 0) { throw "platform test has no facts this evaluator understands" }
    $op = (AttrOr $node 'operator' 'AND').ToUpper()
    $r = if ($op -eq 'OR') { @($arr | Where-Object { $_ }).Count -ge 1 } else { @($arr | Where-Object { -not $_ }).Count -eq 0 }
    if ((AttrOr $node 'negate' 'false') -eq 'true') { -not $r } else { $r }
}
# A rule with no <platform> is applicable; with platforms, it is applicable if any one is true.
# If a platform cannot be evaluated, the rule is treated as applicable (never hidden by an error).
function Test-RuleApplicable($rule) {
    $ps = @($rule.SelectNodes('x:platform', $nsm)); if ($ps.Count -eq 0) { return $true }
    foreach ($p in $ps) {
        $id = $p.GetAttribute('idref').TrimStart('#')
        try { if (-not $Platforms.ContainsKey($id)) { return $true }; $lt = $Platforms[$id].SelectSingleNode('*[local-name()="logical-test"]'); if (Test-CpeLogical $lt) { return $true } } catch { return $true }
    }
    return $false
}

# ---------- run ----------
$started = Get-Date
$prof = $bench.SelectNodes('x:Profile', $nsm) | Where-Object { $_.GetAttribute('id') -like "*$ProfileId" } | Select-Object -First 1
if (-not $prof) { throw "Profile $ProfileId not in the benchmark." }
$selected = @{}; foreach ($s in $prof.SelectNodes('x:select', $nsm)) { $selected[$s.GetAttribute('idref')] = ($s.GetAttribute('selected') -eq 'true') }
$out = New-Object Collections.ArrayList
foreach ($rule in $rules) {
    $rid = $rule.GetAttribute('id'); if ($selected.ContainsKey($rid) -and -not $selected[$rid]) { continue }
    $applicable = Test-RuleApplicable $rule
    if (-not $applicable) {
        [void]$out.Add([pscustomobject]@{ Vuln = ($rule.ParentNode.GetAttribute('id') -replace '.*group_', ''); StigId = $rule.SelectSingleNode('x:version', $nsm).InnerText; Severity = $rule.GetAttribute('severity'); Result = 'notapplicable'
            Title = ($rule.SelectSingleNode('x:title', $nsm).InnerText -replace '\s+', ' '); Finding = "platform: $((@($rule.SelectNodes('x:platform', $nsm)) | ForEach-Object { $_.GetAttribute('idref') -replace '.*platform_', '' }) -join ', ')"; Mdm = ''; Rule = ($rid -replace '.*rule_', '') })
        continue
    }
    $defId = $rule.SelectSingleNode('x:check/x:check-content-ref', $nsm).GetAttribute('name'); $leaves = New-Object Collections.ArrayList
    $ovalResult = try { Get-OvalDefResult $defId $leaves } catch { [void]$leaves.Add(@{ Test = ''; Result = 'error'; Comment = 'evaluator'; Found = $_.Exception.Message }); 'error' }
    $result = switch ($ovalResult) { 'true' { 'pass' } 'false' { 'fail' } 'error' { 'error' } 'not applicable' { 'notapplicable' } default { 'unknown' } }
    $why = @($leaves | Where-Object { $_.Result -ne 'true' -and $_.Result -ne 'not applicable' } | Select-Object -First 3 | ForEach-Object { "$($_.Comment) -> $($_.Found)$(if ($_.Negated) { ' [must NOT be the case]' })" }) -join ' ## '
    if ($result -eq 'pass') { $why = '' }
    [void]$out.Add([pscustomobject]@{
        Vuln = ($rule.ParentNode.GetAttribute('id') -replace '.*group_', ''); StigId = $rule.SelectSingleNode('x:version', $nsm).InnerText; Severity = $rule.GetAttribute('severity'); Result = $result
        Title = ($rule.SelectSingleNode('x:title', $nsm).InnerText -replace '\s+', ' '); Finding = $why; Mdm = $(if ($result -ne 'pass') { Get-MdmEquivalent $leaves } else { '' }); Rule = ($rid -replace '.*rule_', '')
    })
}
$counts = @{}; foreach ($g in ($out | Group-Object Result)) { $counts[$g.Name] = $g.Count }
function C($k) { if ($counts.ContainsKey($k)) { $counts[$k] } else { 0 } }
$scored = (C 'pass') + (C 'fail') + (C 'error') + (C 'unknown'); $score = if ($scored) { [math]::Round(100.0 * (C 'pass') / $scored, 2) } else { 0 }
$decided = (C 'pass') + (C 'fail'); $scoreDecided = if ($decided) { [math]::Round(100.0 * (C 'pass') / $decided, 2) } else { 0 }
$bmId = "$($bench.GetAttribute('id') -replace '.*benchmark_', '') $($bench.SelectSingleNode('x:version', $nsm).InnerText)"
$partial = if ($script:Elevated) { '' } else { ' | PARTIAL (not elevated)' }
$lines = New-Object Collections.ArrayList
[void]$lines.Add("RESULT: $Machine | $bmId | profile $ProfileId | score $score of 100 | pass=$(C 'pass') fail=$(C 'fail') error=$(C 'error') unknown=$(C 'unknown') notapplicable=$(C 'notapplicable') of $($out.Count) rules$partial")
[void]$lines.Add("        score over rules that could be decided (pass+fail): $scoreDecided | by severity, failed: high=$(@($out | Where-Object { $_.Result -eq 'fail' -and $_.Severity -eq 'high' }).Count) medium=$(@($out | Where-Object { $_.Result -eq 'fail' -and $_.Severity -eq 'medium' }).Count) low=$(@($out | Where-Object { $_.Result -eq 'fail' -and $_.Severity -eq 'low' }).Count)")
$mdmFails = @($out | Where-Object { $_.Result -eq 'fail' -and $_.Mdm }).Count
[void]$lines.Add("        failures with a same-named MDM-store value (check by hand; may be the setting delivered by Intune): $mdmFails of $(C 'fail')")
[void]$lines.Add("        evaluated by REF-Eval-STIG.ps1 (PowerShell OVAL evaluation of DISA's benchmark content; not SCC) | $($started.ToString('yyyy-MM-dd HH:mm')) | $([int]((Get-Date) - $started).TotalSeconds) s | user elevated=$($script:Elevated)")
[void]$lines.Add('')
foreach ($grp in 'fail', 'error', 'unknown') {
    $set = @($out | Where-Object Result -eq $grp | Sort-Object @{ e = { @{ high = 0; medium = 1; low = 2 }[$_.Severity] } }, StigId)
    if ($set.Count) { [void]$lines.Add("--- $($grp.ToUpper()) ($($set.Count)) ---"); foreach ($r in $set) { [void]$lines.Add(("{0} {1} [{2}] {3}" -f $r.Vuln, $r.StigId, $r.Severity, $r.Title)); [void]$lines.Add("      $($r.Finding)"); if ($r.Mdm) { [void]$lines.Add("      MDM store: $($r.Mdm)") } } ; [void]$lines.Add('') }
}
$lines | ForEach-Object { $_ }
if (-not $NoFiles) {
    $dest = Join-Path $EvidenceRoot ("{0}\stig-eval-{1}" -f (Get-Date -Format 'yyyy-MM-dd'), $Machine.ToLower()); New-Item -ItemType Directory -Force $dest | Out-Null
    $stamp = Get-Date -Format 'HHmmss'
    [IO.File]::WriteAllLines((Join-Path $dest "summary-$stamp.txt"), [string[]]$lines, (New-Object Text.UTF8Encoding($false)))
    $out | Export-Csv (Join-Path $dest "results-$stamp.csv") -NoTypeInformation -Encoding UTF8
    "evidence: $dest (summary-$stamp.txt, results-$stamp.csv)"
}
