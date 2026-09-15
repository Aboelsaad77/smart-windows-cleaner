# Risk Engine

The risk engine scores the **risk of deleting** a file (0–100). It is *not* a
junkiness score — a 10-year-old installer and a system DLL are both judged by
"what happens if we remove this".

## Bands (spec §5)

| Score | Band | Meaning |
|---|---|---|
| 0–10 | `VERY_SAFE` | Junk almost certainly |
| 11–30 | `SAFE` | Eligible for one-click cleanup (still goes to quarantine) |
| 31–60 | `REVIEW` | User confirms each item |
| 61–85 | `DANGEROUS` | User confirms with strong warning |
| 86–100 | `PROTECTED` | Treated as never-delete |

Baseline: **50** (unknown context ⇒ review).

## Scoring table

| Rule | Delta | When |
|---|---|---|
| `TEMP_PATH` | −25 | Path inside a known temporary folder |
| `BROWSER_CACHE` | −20 | Path inside a browser *cache* directory (never the profile) |
| `TEMP_KIND` | −10 | Content kind = temp (and not already a temp path) |
| `CACHE_KIND` | −15 | Content kind = cache (and not already a browser cache path) |
| `LOG_KIND` | −10 | Content kind = log |
| `TEMP_EXT` | −10 | Extension in `.tmp .temp .dmp .chk .swp .old` (outside temp dirs) |
| `INSTALLER_KIND` | −10 | Content kind = installer |
| `OLD_INSTALLER` | −25 | Installer older than 60 days (re-downloadable) |
| `AGE_30D` | −10 | Not modified for > 30 days |
| `AGE_90D` | −5 | Not modified for > 90 days (on top of AGE_30D) |
| `DRIVER` | +50 | Kernel driver |
| `WINDOWS_COMPONENT` | +60 | Protected Windows component path |
| `IN_USE` | +80 | Locked / used by a running process |
| `HIDDEN` | +5 | Hidden file |
| `PE_EXECUTABLE` | +40 | PE binary (not identified as installer) |
| `PE_INSTALLER` | +20 | PE binary identified as an installer |
| `LIBRARY` | +35 | `.dll` / `.ocx` / non-driver `.sys` |
| `SIGNED_BINARY` | +30 | Digitally signed PE |
| `UNSIGNED_PE` | +30 | Unsigned PE (unknown origin) |
| `PERSONAL_AREA` | +15 | Documents/Desktop/Pictures/Videos/Music |
| `PERSONAL_CONTENT` | +10 | Document/media inside a personal area |

Post-processing: clamp to 0–100; if `in_use` the score is floored at 95.

## Worked examples (all covered by unit tests)

| File | Math | Score | Band |
|---|---|---|---|
| `Temp\abc.tmp` (10 d) | 50 −25 | 25 | SAFE |
| Chrome `Cache\f_000001` (184 d) | 50 −20 −10 −5 | 15 | SAFE |
| `chrome.dll` (signed PE) | 50 +35 +30 | 100 | PROTECTED |
| `System32\drivers\foo.sys` | 50 +50 +60 | 100 | PROTECTED |
| `chrome.exe` (in use) | 50 +40 +30 +80 | 100 | PROTECTED |
| `Documents\resume.docx` | 50 +15 +10 | 75 | DANGEROUS |
| `Downloads\crack.exe` (unsigned) | 50 +40 +30 | 100 | PROTECTED |
| `Downloads\vs-setup.exe` (signed, 400 d) | 50 −10 −10 −5 −25 +20 +30 | 50 | REVIEW |
| `D:\Games\gta.iso` (200 d) | 50 −10 −5 | 35 | REVIEW |

## Explainability (spec §17)

Every assessment carries its `RiskFactor` list; `explanation()` renders it as
"−25 TEMP_PATH — File lives in a known temporary folder", which is exactly
what the Results page shows under *Why?*.

## Notes / tuning

- Numbers are the v1 constants in `sc-risk-engine`. They are deliberately
  conservative: when in doubt, the file lands in REVIEW, and the safety
  engine still has the last word.
- "Old does not mean junk" (spec §13): age only ever *lowers* risk for files
  that already look like junk; it can never make a document or media file
  deletable.
