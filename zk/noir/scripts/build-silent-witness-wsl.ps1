$ErrorActionPreference = "Stop"

$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
if ($repo -notmatch "^([A-Za-z]):\\(.*)$") {
  throw "Expected a Windows absolute path, got $repo"
}

$drive = $Matches[1].ToLower()
$rest = $Matches[2] -replace "\\", "/"
$wslRepo = "/mnt/$drive/$rest"

wsl bash -lc "chmod +x '$wslRepo/zk/noir/tools/jq'; export PATH='$wslRepo/zk/noir/tools':/home/enliven/.nargo/bin:/home/enliven/.bb:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; cd '$wslRepo'; python3 zk/tools/build_circuits.py build silent_witness --prove"
