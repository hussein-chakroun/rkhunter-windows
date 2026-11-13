# Local Windows indicators

`data/windows-indicators.json` contains exact whole-file SHA256 hashes and paths.
It does not accept executable code, URLs, regexes or path wildcards. Supply
verified indicators from your own trusted source. The default arrays are empty.

```json
{
  "schemaVersion": 1,
  "version": "your-reviewed-revision",
  "sha256": [
    {
      "hash": "REPLACE_WITH_AN_ACTUAL_64_CHARACTER_SHA256_HASH",
      "name": "Your source's indicator description"
    }
  ],
  "paths": [
    {
      "path": "%SystemRoot%/System32/drivers/your-reviewed-indicator.sys",
      "name": "Your source's exact path indicator"
    }
  ]
}
```

The placeholder hash above intentionally fails validation. A path match is
a heuristic; a name alone does not establish malware. Hash inspection covers
the monitored property files and the bounded configured scan directories.
It does not hash every process, every installed driver or every disk file.

To import a reviewed revision, prepare a separate local directory containing
`windows-indicators.json` and `manifest.json`. Generate the manifest in PowerShell:

```powershell
$source = 'C:\Trusted\rkhunter-data'
$file = Join-Path $source 'windows-indicators.json'
@{
    schemaVersion = 1
    file = 'windows-indicators.json'
    sha256 = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $source 'manifest.json') -Encoding UTF8
```

Then import and validate:

```powershell
.\rkhunter.cmd --update --update-source C:\Trusted\rkhunter-data
.\rkhunter.cmd --config-check
.\rkhunter.cmd --check --enable known_rkts,hashes
```

Exit code `2` from `--update` means data changed. A failed checksum or schema
leaves the installed indicators intact. The importer stages a copy so validation
and installation use the same bytes. It has no release feed, signature
verification, freshness guarantee or rollback prevention; the source must
already be trusted. `UPDATE_SOURCE` in the config can supply the default source.

The indicators are themselves property-monitored. After reviewing an update,
you may refresh only that entry with:

```powershell
.\rkhunter.cmd --propupd windows-indicators.json
```
