Rootkit Hunter for Windows is a modified, independently maintained adaptation,
not an official upstream Windows release.

The supplied source tree was copied from:
`C:\Users\legion\Downloads\rkhunter-master\rkhunter-master`.
The source files identify Rootkit Hunter 1.4.6 and include a June 2017 manual;
the supplied archive's filesystem dates are February 2018. These are historical
inputs, not current Windows malware intelligence.

Upstream attribution: The Rootkit Hunter project, Copyright (c) 2003-2018,
Michael Boelen, and contributors. Additional author and copyright notices are
preserved in `upstream/`. See `upstream/files/ACKNOWLEDGMENTS`.

The Windows implementation, command launchers, installer, configuration,
documentation and tests were added on 2026-11-13. The original shell scanner
and installer were preserved in `upstream/` as reference source, together with
the original documentation, translations and signatures. `SHA256SUMS.json`
records the SHA256 of each file in the supplied source directory. An additional
`upstream/files/.gitignore` ensures the original development scripts are included
in Git despite the original ignore rules; no original source file was modified.

The Windows adaptation is distributed under the GNU GPL version 2 or later,
consistent with upstream's source notice. A copy of GPL version 2 is in
`LICENSE`. Existing upstream notices and any more specific notices in individual
files continue to apply. `data/backdoorports.dat` is an unmodified copy of the
upstream legacy port database. No claim is made that these Unix-era port
indicators identify Windows malware.
