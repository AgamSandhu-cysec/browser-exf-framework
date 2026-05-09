# Project pause — ext-attack-framework Phase 3 (dynamic / Puppeteer)

**Paused:** 2026-05-04  
**Branch / state:** working tree with Phase 3 harness + orchestrator changes (not necessarily committed).

---

## Where we stopped

Work was paused while **hardening the Node harness + Python orchestrator** after the main Phase 3 feature set was implemented:

- Puppeteer harness under `dynamic/harness/` (`runner.js`, `setup.js`, utils, four test modules).
- Python `dynamic/orchestrator.py` spawning `node runner.js --ext-path <abs>`, JSON → `Finding`.
- CLI `--dynamic`, fixture `tests/fixtures/dynamic_vuln_ext/` (including **external** `harness_bridge.js` so extension CSP does not block the bridge).
- Local **second HTTP port** CORS probe (`HARNESS_CORS_LEAK_BODY`) so scans do not depend on `httpbin.org`.
- **Unique Chrome `--user-data-dir`** per run (`runner.js` + `setup.js`) to reduce `SingletonLock` / profile clashes between runs.
- Orchestrator switched to **`subprocess.Popen` + `start_new_session`** (POSIX) and **`os.killpg(..., SIGKILL)`** on timeout so orphaned Chrome from Puppeteer does not leave the parent `node` process stuck until Python’s `timeout=` fires.
- XSS tests **parallelized per payload** so the module stays within the **30s** per-module budget; **`browser.targets()`** / **`bg.page()`** wrapped with timeouts.
- CI (`.github/workflows/ci.yml`): Node 20, `npm install` in `dynamic/harness`, `xvfb-run` for tests.
- Slow pytest: **skip on Linux if `DISPLAY` is unset** (headed Chrome); README notes `xvfb-run -a pytest … -m slow`.

The last in-session verification was **inconsistent** (local `node runner.js` could finish in ~40–50s with all four dynamic modules; **`pytest -m slow` sometimes hit the 180s orchestrator timeout** before subprocess/killpg hardening; the agent environment sometimes **aborted** shell runs before completion).

---

## What is left (resume here)

1. **Verify locally (authoritative)**  
   - `python -m pytest tests/ -v -m "not slow"`  
   - `xvfb-run -a python -m pytest tests/test_dynamic_orchestrator.py -v -m slow`  
   - `xvfb-run -a python cli.py scan --input tests/fixtures/dynamic_vuln_ext --dynamic --format terminal`  

2. **Confirm orchestrator subprocess**  
   - After `_run_harness_subprocess` + `killpg` changes, confirm the slow test **always** returns findings under `xvfb-run` within **well under 180s** (target ~60s).  
   - If anything still hangs, add logging (harness stderr milestones) or shorten budgets; avoid regressing the 30s/module / 120s total harness rules unless you intentionally change the spec.

3. **Optional polish**  
   - Deduplicate `openBridge` between `cors_proxy_tester.js` and `background_injector.js`.  
   - Node `SIGTERM`: optionally **await** `forceCloseBrowser` so `timeout(1)` kills a clean tree (tricky in signal handler; low priority).  
   - README: one short “Troubleshooting” line for stuck Chrome / `SingletonLock` (already mitigated by temp profile).

4. **Commit / tag**  
   - Review diff, commit with a clear message, run CI workflow mentally against the YAML you have.

---

## Problems encountered (for the next session)

| Issue | What we did / notes |
|--------|----------------------|
| **Headed Chrome needs a display** | Extensions do not run in headless; Linux CI and SSH need `xvfb-run` (or a real DISPLAY). Slow test skips if `DISPLAY` is missing on Linux. |
| **Subprocess appeared to run full 180s then return `[]`** | Often explained by **Chrome surviving past `node`** or **`browser.close()`** stalling; mitigated by **`killpg`**, bounded **`browser.close()`**, and unique **`user-data-dir`**. |
| **Harness bridge `__harnessSend` never defined** | Extension **CSP blocks inline script**; fixed by **`harness_bridge.js`** + `web_accessible_resources`. |
| **`httpbin.org` unreachable** | DNS/network in some environments; replaced primary CORS check with **local second-origin** server. |
| **XSS module exceeded 30s** | Many sequential navigations; fixed by **parallel probes** per payload. |
| **`bg.page()` / `browser.targets()` hang** | Wrapped with **timeouts** and polling limits. |
| **`browser.pages()` in cleanup could hang** | **4s race** in `closeOrphanHarnessPages`; **`forceCloseBrowser`** avoids listing pages where possible. |
| **Agent/sandbox shell “Aborted” or no output** | Environment/tooling flakiness, not necessarily your repo; **always re-run on your machine**. |

---

## How much of the project is left (rough %)

| Area | Status | Approx. |
|------|--------|-----------|
| Static analysis (Phases 1–2) | Done / maintained | **100%** |
| Dynamic harness + tests + fixture | Implemented | **~90%** |
| Orchestrator + CLI integration | Implemented + hardened | **~90%** |
| **Reliability & proof** (slow test + full CLI under xvfb on clean Linux) | Needs your confirmation | **~10%** |
| Optional cleanup (DRY bridge, docs tweaks) | Nice-to-have | **~5%** |

**Overall Phase 3:** about **85–90% complete**; the remaining slice is mostly **“prove it green everywhere we care about”** and small polish—not greenfield implementation.

---

## Quick file map (dynamic stack)

| Path | Role |
|------|------|
| `dynamic/orchestrator.py` | `npm install` if needed, `_run_harness_subprocess`, JSON → `Finding` |
| `dynamic/harness/runner.js` | Launches Chrome, servers, runs modules, prints JSON array |
| `dynamic/harness/setup.js` | `puppeteer.launch` + extension args + `userDataDir` |
| `tests/fixtures/dynamic_vuln_ext/` | Vulnerable MV2 ext + `harness_bridge.html` / `.js` |
| `tests/test_dynamic_orchestrator.py` | Mocks + `@pytest.mark.slow` E2E |

When you resume, start by running the three commands in **§ What is left → (1)** and fix only what fails.
