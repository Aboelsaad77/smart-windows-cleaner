# Smart Cleaner

**AI-Assisted Windows Storage Intelligence & Safe Cleanup** — a Windows desktop app
that finds what can safely be removed from your drives — and *proves why* — before
it touches anything.

> **The AI proposes. The Safety Engine decides.**
> Nothing is ever deleted directly: every removal goes through a **Quarantine Vault**
> you can restore from at any time.

---

## Why another cleaner?

Classic cleaners list files and say "delete". Smart Cleaner explains:

- **Storage Analyzer** — see where your disk space actually goes, with drill-down.
- **Cleanup** — temp files, caches, old installers, each with a per-item
  *risk of deletion* score and a "Why?" explanation.
- **Insights** — large files, duplicates, data untouched for 12+ months.
- **Quarantine + Rollback** — reversible "deletion" with configurable retention
  (1 / 7 / 30 days, or never).

> **Arabic:** ملخص بالعربي في نهاية الملف.

## Core guarantees (safety invariants)

1. The scanner only discovers. It **cannot** delete.
2. Deletion risk is scored 0–100. **86–100 (Protected) is never deletable.**
3. Hard rules override *everything* — including AI: Windows paths, system files,
   drivers, in-use files, signed binaries → `NEVER_DELETE`.
4. Unsigned executables are **never** auto-deleted.
5. AI (when enabled later) only gives a second opinion on ambiguous files.
   It never receives file content and never has delete permission.
6. The program cannot delete itself, its own vault, or any user-excluded path.
7. Every action is written to a local audit log.

## Architecture

```text
Electron/React UI (M2)
      │ IPC / local API (sidecar)
      ▼
Native Core (Rust) — core/
  scanner → risk-engine → SAFETY-ENGINE (final gate)
                              │ blocked │ quarantined
      ai-gateway (optional signal)    quarantine vault (restore / retention)
      db: SQLite — local only
```

Details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) ·
[docs/RISK-ENGINE.md](docs/RISK-ENGINE.md) ·
[docs/SAFETY.md](docs/SAFETY.md) ·
[docs/QUARANTINE.md](docs/QUARANTINE.md) ·
[docs/DATABASE.md](docs/DATABASE.md) ·
[docs/ROADMAP.md](docs/ROADMAP.md) ·
[Original spec (Arabic)](docs/SPEC-ar.md)

## Repository layout

```text
core/
  crates/file-models     shared types (FileRecord, RiskBand, AiSignal, heuristics)
  crates/scanner         Filesystem Discovery Engine (quick/smart/deep)
  crates/risk-engine     0–100 deletion-risk scoring, explainable
  crates/safety-engine   FINAL GATE: hard rules beat everything, incl. AI
  crates/quarantine      reversible-delete vault (hash-verified restore)
  crates/db              local SQLite persistence
  crates/ai-gateway      optional AI second-opinion (off by default in v1)
  crates/cli             sc-cleaner — reference CLI / future IPC sidecar
docs/                    architecture, safety, risk, quarantine, db, roadmap, spec
```

## Getting started

```bash
cd core
cargo test --workspace          # run everything (Linux + Windows)
cargo run -p sc-cli -- --quick /path/to/scan
```

### Sample output (M0 demo)

```text
$ sc-cleaner --smart /tmp/sc-demo

files: 7   total: 989.1 MiB   (0 errors)
auto-quarantine eligible:     110.0 MiB
needs user confirmation:      879.1 MiB
blocked (never delete):         0.0 MiB

      MiB        band score  verdict          path
    800.0      REVIEW   40  user-confirm     Downloads/big-install-setup.exe
    79.1      REVIEW   50  user-confirm     Games/gta-v.iso
    60.0        SAFE   30  auto-quarantine  AppData\Local\Google\Chrome\...\Cache\f_000001
    50.0        SAFE   25  auto-quarantine  AppData\Local\Temp\old-junk.tmp
     0.0   DANGEROUS   75  user-confirm     Documents/resume.docx
     0.0   DANGEROUS   85  never-delete     Windows\System32\drivers\nvlddmkm.sys
     0.0   DANGEROUS   85  user-confirm     Program Files\Google\Chrome\chrome.dll
```

Every line is a decision the Safety Engine made — the UI (M2) renders the
same data with per-item *Why?* explanations.

## Status

**M0 ✅** — core engine complete and tested (scanner, risk, safety, quarantine,
DB, AI-gateway skeleton, CLI). See [docs/ROADMAP.md](docs/ROADMAP.md) for M1–M5
(Windows native depth → Electron/React UI → optional AI → insights → packaging).

---

## ملخص بالعربي

سمارت كلينر مش مجرد برنامج تنظيف — ده **استخبار تخزين + تنظيف آمن بمساعدة AI**:

- الـAI **يقترح** ويحلل، لكن **طبقة الأمان هي اللي تقرر**. لو أمان قال لا → لا، حتى لو الـAI قال احذف.
- مفيش حذف مباشر أبدًا: كل شيء بينقل لـ **Quarantine** مع hash كامل، وتقدر ترجعه في أي وقت، والـ delete النهائي يبقى بعد فترة (يوم/أسبوع/شهر) أو بترتيب صريح منك.
- كل ملف بيتقيّم بـ **درجة خطر حذف من 0 لـ100** مع شرح "ليه؟" — مش "Clean 6.2 GB" من غير تفسير.
- قواعد صارمة أعلى من كل حاجة: ملفات Windows، الدرايفرات، الملفات المستخدمة دلوقتي، الـ binaries الموقعة → **ممنوع مساس**. الـ executables غير الموقعة عمرها ما تتحذف أوتوماتيك.
- البرنامج يحمي نفسه ومجلده، ويحترم قوائم "مسّاهاش" الخاصة بيك.
- كل عملية بيتسجل في **Audit Log** محلي.
- **v1 بدون AI cloud** (زي ما المضمون بيقترح): كل حاجة شغالة أوفلاين، والـAI يضاف بعدين كـ second opinion للحالات الغامضة فقط — ومتتعرضش محتوى الملفات.
