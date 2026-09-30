# UI validation — 12 September 2026

## Verified

- Browser checks at 375 × 812, 812 × 375, and 1440 × 900, using representative pages (not every page at every size).
- Phone homepage, marketplace, login, developer registration, admin dashboard, developer dashboard, user library, and app detail inspected.
- Desktop marketplace and populated admin dashboard inspected.
- Homepage pause switches to Resume and exposes its pressed state.
- Marketplace mobile navigation expands and exposes its expanded state.
- Login password visibility works; keyboard Tab moves from the visibility control to Remember me.
- Phone user-library overflow corrected and rechecked; landscape library/login fit the viewport.
- Marketplace workflow regression test passes.

## Fixes

- Follow-up: admin mobile drawer now skips hidden links, keeps keyboard focus inside the open menu, announces expanded state, and restores focus on Escape. Browser-tested at 375px, including Shift+Tab wrapping.
- Admin, user, and developer dashboards rechecked at 320px: no page-level horizontal overflow. This is a narrow-screen reflow check, not a substitute for 200% text scaling.
- Added `node _ui_motion_test.cjs`: passing unit checks for reduced-motion settings, pause toggles, and hidden-document pausing on both animation scripts. Actual OS/browser motion emulation remains unverified.

- Dark-theme contrast for back links, account-type tabs, marketplace description, active navigation, dashboard filters, review shortcut, and app-detail panels.
- Member navigation stays available on phones instead of disappearing.
- Library cards adapt to narrow screens.
- Accessible names for mobile navigation, library download/remove controls, notifications, and sign-out.
- Reduced-motion CSS now stops legacy inner-page animations as well as the new cube.

## Test setup and limits

Authenticated pages were rendered from disposable workflow-test data through an optional read-only preview. No real accounts or uploads were changed. Its dummy APK icon is not a valid image; broken fixture icons are not evidence of a production image failure. Live updates and form submissions are deliberately unavailable in this snapshot preview.

Still required for full accessibility sign-off: actual screen-reader testing, browser/OS reduced-motion emulation, 200% text/zoom checks, and a complete contrast audit of every page and error state. Current browser checks are a representative UI pass, not WCAG certification. Production load, email/scanner integration, and deployment checks remain separate tasks.

To repeat the optional preview in PowerShell:

```powershell
$env:UI_PREVIEW_PORT = '5012'
env/Scripts/python.exe _marketplace_workflow_test.py
```

Open `/admin`, `/user/dashboard`, `/developer/dashboard`, or `/apps/workflow-app` on localhost port 5012. Stop with Ctrl+C and clear `UI_PREVIEW_PORT` before a normal uninterrupted test run.
