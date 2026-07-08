# Plan: Server-Driven Derived View Generation & Snapshot Ring Buffer Fix

## Context

Two related problems exist in how Skannr generates derived data (Subject History,
hourly snapshots, Insights, Reports):

### Problem 1: All derived generation is browser-driven

Subject history rebuilds, snapshot creation, and derived view refreshes only
happen when the browser sends `POST /derived_views/refresh`. This POST is
triggered by:

| Trigger | Where | When |
|---|---|---|
| Manual Refresh button | app.js click handler | User clicks |
| Auto-refresh timer | `scheduleAutoDerivedRefresh()` in app.js | Every 15 min (browser-side `setTimeout`) |
| Catch-up | `maybeRefreshEmptyDerivedViews()` in app.js | Live SSE events arrive, derived views empty |
| View change | Window dropdown handler | User changes time window |

There is **no server-side background task** that periodically rebuilds derived
views. The `device_history_worker_loop` only compacts raw WiFi/BLE/LAN events;
it does not call `refresh_subject_history()` or `_save_hourly_snapshot()`.

### Problem 2: Only 1-2 snapshot files instead of 24

`_save_hourly_snapshot()` is a side effect of `refresh_subject_history()`. It
creates at most one snapshot per clock hour (filename-based dedup). Since
subject history only rebuilds when the browser is connected and triggering
refreshes, the snapshot ring buffer never fills. A fresh T02 file appearing at
02:49 confirms this — it was created when a refresh happened to run then, not
because of any hourly schedule.

### Root cause

The server has no autonomous scheduler for derived view generation. Everything
is reactive to browser HTTP requests. When no browser tab is open, no snapshots
accumulate. When a browser connects briefly, it creates exactly one snapshot for
the current hour then stops.

## Desired Outcome

1. Server autonomously rebuilds derived views on a schedule → hourly snapshots
   accumulate naturally → the 24-hour ring buffer is always populated.
2. UI simplifies to poll-and-load: check if the server has new data, fetch and
   render if so. No more triggering rebuilds from the browser (manual refresh
   still available as an explicit force-rebuild).
3. Missing snapshots from gaps are backfilled using already-materialized subject
   history data.

## Implementation Plan

### General: Tracing

Every new background operation (scheduler cycles, backfill, individual rebuild
phases) must log structured tracing to `skannr.log` with `elapsed=%.2fs` timing.
Follow the existing pattern from `refresh_subject_history()`:

```
logging.info(
    "derived subject_history pending check finished elapsed=%.2fs ...",
    time.monotonic() - started, ...
)
```

Specific trace points to add:
- **Scheduler cycle start/finish** — log when each periodic rebuild begins and ends, with total elapsed
- **Scheduler skip** — log when a cycle is skipped because another refresh is active
- **Backfill scan** — log number of existing snapshots, missing hours found, and elapsed
- **Backfill per-hour** — log how many snapshots were built and written
- **Backfill skip** — log when backfill finds nothing to do (all 24h covered, or no cached SH)
- **`data_version_epoch` computation** — not traced (trivial, runs in `build_cached_derived_bundle`)

### Phase 1: Server-side config key

**File: `src/skannr/main.py`**

Add a new function (modeled on the existing `device_history_update_interval_sec()`
at line 2493):

```python
def derived_scheduler_interval_sec():
    """Return server-side derived-data rebuild interval in seconds.

    Reads ``ui.derived_scheduler_interval_sec`` from config/skannr.yaml.
    Default 900 (15 min). Values 1-59 are clamped to 60. 0 disables.
    """
```

**File: `config.example/skannr.yaml`**

Add after `derived_auto_refresh_min: 15` (line 347):
```yaml
  # Server-side autonomous derived-data rebuild interval in seconds.
  # 0 disables the scheduler. Default 900 (15 min).
  derived_scheduler_interval_sec: 900
```

### Phase 2: Background scheduler thread

**File: `src/skannr/main.py`**

Add two functions following the pattern of the existing
`device_history_worker_loop` / `start_device_history_worker` (lines 2505–2532):

```python
def derived_refresh_scheduler_loop(interval_sec):
    """Background thread: periodically rebuild all derived views.

    Runs independently of browser connections. Uses the same
    DerivedRefreshCoordinator lock as manual browser refreshes so
    they never collide.
    """

def start_derived_refresh_scheduler():
    """Launch the background derived-data rebuild scheduler thread."""
```

**Key design decisions:**
- Uses `threading.Thread` (not an asyncio task) because `build_summary()` does
  synchronous file I/O that can take tens of seconds. This follows the pattern
  of `device_history_worker_loop` and `run_background_derived_refresh`.
- The first rebuild waits a short grace period (~30s) so collectors produce
  initial JSONL data before the first rebuild.
- If `derived_refresh.is_active()` is True (e.g., a manual refresh is in
  progress), the scheduler skips that cycle.
- If `build_derived_views(force=True)` takes longer than the interval, the next
  cycle finds the lock held and skips — no stacking.

**Wire into `main()`** (line 5495): call `start_derived_refresh_scheduler()`
after `start_device_history_worker()` and before `run_web_listeners()`.

### Phase 3: Snapshot backfill on startup

**File: `src/skannr/main.py`**

Add `backfill_missing_snapshots()` — runs once at startup before the scheduler's
first cycle:

```python
def backfill_missing_snapshots():
    """Build hourly snapshots for missing hours in the past 24h.

    Reads the persisted subject_history.json and builds snapshots
    for any hour that has subject data but no snapshot file on disk.
    Best-effort: hours predating the cached subject history won't
    have data to backfill. The scheduler fills those going forward.
    """
```

Key behaviors:
- Scans `sh_snapshots/` for gaps in the past 24 hours
- Reads cached `subject_history.json` (via `read_json_file(subject_history_path())`)
- Calls `build_snapshot_from_sh(sh_dict, hour_epoch=hour)` for each missing hour
- Skips hours where the subject history has no subjects with `last_seen_epoch`
  in that window
- Calls `save_snapshots()` to persist and purge
- Gracefully handles: no cached SH (fresh install), disk errors, already-filled gaps

**Wire into `main()`**: call `backfill_missing_snapshots()` after
`start_device_history_worker()` and before `start_derived_refresh_scheduler()`.

### Phase 4: Add `data_version_epoch` to derived bundle

**File: `src/skannr/main.py` — `build_cached_derived_bundle()` (line 2317)**

After the bundle dict is constructed (~line 2348, before
`compact_derived_bundle_for_browser`), compute a stable version timestamp:

```python
# Compute a stable data-version from the underlying section summaries.
# This only changes when the scheduler (or manual refresh) rebuilds data.
# The browser uses it to skip redundant DOM re-renders during polling.
with runtime["derived_cache_lock"]:
    section_epochs = [
        summary_generated_epoch(runtime.get("subject_history")),
        summary_generated_epoch(runtime.get("device_history")),
        summary_generated_epoch(runtime.get("history_analysis")),
        summary_generated_epoch(runtime.get("reports")),
    ]
section_epochs = [e for e in section_epochs if e is not None]
bundle["data_version_epoch"] = (
    max(section_epochs) if section_epochs else generated_at_epoch
)
```

This is additive — old browsers ignore it. `compact_derived_bundle_for_browser`
passes top-level keys through.

### Phase 5: UI simplification

**File: `src/skannr/static/app.js`**

#### 5a: Add state variable (~line 86)

```javascript
let lastRenderedDataVersionEpoch = 0;
```

#### 5b: Replace auto-refresh with polling

Replace `refreshDerivedViewsAutomatically` (line 2390) and modify
`scheduleAutoDerivedRefresh` (line 2375):

```javascript
function pollDerivedViewsForChanges() {
  // Poll GET /derived_views (fetch-only, no rebuild).
  // Compare data_version_epoch to skip no-op renders.
  const requestWindow = activeWindow || "default";
  fetchJson(`/derived_views?days=${encodeURIComponent(requestWindow)}`)
    .then((bundle) => {
      if (!bundle || bundle.refresh_in_progress) return;
      const versionEpoch = Number(bundle.data_version_epoch
        || bundle.generated_at_epoch || 0);
      if (versionEpoch > lastRenderedDataVersionEpoch) {
        renderDerivedViews(bundle);
      }
    })
    .catch(() => { /* silently retry next cycle */ })
    .finally(() => { scheduleAutoDerivedRefresh(); });
}
```

`scheduleAutoDerivedRefresh()` now sets a timeout for `pollDerivedViewsForChanges`
instead of `refreshDerivedViewsAutomatically`. The interval still reads from
`derived_auto_refresh_min`.

#### 5c: Record version on render

In `renderDerivedViews` (after the `maybeRefreshEmptyDerivedViews` call at ~line 1753):

```javascript
const versionEpoch = Number(
  (bundle || {}).data_version_epoch
  || (bundle || {}).generated_at_epoch || 0
);
if (versionEpoch > lastRenderedDataVersionEpoch) {
  lastRenderedDataVersionEpoch = versionEpoch;
}
```

This covers both the auto-poll and manual-refresh code paths.

#### 5d: Simplify catch-up to load-only

`maybeRefreshEmptyDerivedViews` (line 1982): change from calling
`refreshDerivedViews("catch-up")` (which POSTs a rebuild) to calling
`requestDerivedLoad("catch-up: ...")` (which GETs existing data). The server
scheduler keeps data current; catch-up just needs to load it.

`maybeRefreshMissingSubject` (line 2001): same treatment — use
`requestDerivedLoad` instead of `refreshDerivedViews`.

Remove `catchUpRefreshAllowed` (line 2012) — its only callers were the two
functions above.

#### 5e: Remove stale-refresh auto-trigger

Remove `shouldRunStaleDerivedRefresh` (line 2403) and its call in
`updateDerivedStatusLines` (~line 2270). Keep the staleness *display* text
(`derivedStaleText`, `derivedDataStatusState`) as visual indicators.

#### 5f: Manual refresh preserved

The Refresh buttons continue to call `refreshDerivedViews("manual")` →
`runDerivedRefresh("manual")` → POST `/derived_views/refresh`. Unchanged.

The window-change handler continues to call `refreshDerivedViews("view")`.
Unchanged.

## Interaction Matrix

| Scenario | Behavior |
|---|---|
| Normal operation | Scheduler rebuilds every 15 min. Snapshots created hourly. Browser polls GET every 15 min, renders only when `data_version_epoch` changes. |
| Server restart | Backfill fills gaps from cached SH. Scheduler starts after 30s grace. |
| Fresh install (no data) | Backfill skips (empty SH). Scheduler's first rebuild finds no JSONL. |
| Manual refresh during scheduler cycle | POST sees `refresh_in_progress`, browser polls status, renders when done. |
| Scheduler fires during manual refresh | `derived_refresh.is_active()` → True → scheduler skips, waits for next interval. |
| Browser not connected | Scheduler runs autonomously. Snapshots accumulate. Ring buffer fills. |
| Scheduler disabled (`interval=0`) | Falls back to old behavior. Browser still polls GET. Manual refresh still works. |

## Files Modified

| File | Changes |
|---|---|
| `src/skannr/main.py` | Add `derived_scheduler_interval_sec()`, `derived_refresh_scheduler_loop()`, `start_derived_refresh_scheduler()`, `backfill_missing_snapshots()`. Add `data_version_epoch` to `build_cached_derived_bundle()`. Wire into `main()`. |
| `src/skannr/static/app.js` | Add `lastRenderedDataVersionEpoch`. Replace auto-refresh with poll. Simplify catch-up. Remove `shouldRunStaleDerivedRefresh` and `catchUpRefreshAllowed`. Record version in `renderDerivedViews`. |
| `config.example/skannr.yaml` | Add `derived_scheduler_interval_sec: 900` to `ui:` section. |

## Phased Rollout

Phases 1–4 can be deployed together (server becomes autonomous, browser still
does POST refreshes too — both work, the coordinator lock prevents conflicts).
Phase 5 follows after verifying the scheduler is working correctly in production.

## Verification

1. **Server scheduler**: Start the app, wait for the scheduler's first cycle.
   Check `skannr.log` for "derived scheduler triggering periodic rebuild" and
   "hourly snapshot saved" messages.

2. **Snapshot ring buffer**: After the app runs for >1 hour, check
   `runtime/logs/sh_snapshots/` — should have at least 1 snapshot per completed
   hour. After 24 hours of uptime, should have ~24 files.

3. **Backfill**: Restart the app. Check logs for "snapshot backfill" messages.
   Verify previously missing hours now have snapshot files.

4. **UI polling**: Open the browser dashboard. Watch the Network tab — should
   see periodic GET requests to `/derived_views`, NOT POST to
   `/derived_views/refresh` (except when clicking the Refresh button).

5. **Regression**: Run `python3 scripts/skannr_regression_test.py` and
   `python3 scripts/validate_collector_contract.py` — all checks must pass.

6. **Manual refresh**: Click the Refresh button — should still trigger a full
   rebuild via POST and render updated data.
