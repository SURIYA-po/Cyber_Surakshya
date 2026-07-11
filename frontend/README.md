# Cyber Surakshya — SOC Dashboard (Frontend)

React + Vite + Tailwind CSS v4 frontend for the Security Operations Center
platform. This is a presentation/control layer only — all security logic
lives in the FastAPI backend.

## Getting started

```bash
npm install
npm run dev
```

The app runs at `http://localhost:5173`.

By default it points at `http://localhost:8000` for the API (see `.env`).
Change `VITE_API_BASE_URL` in `.env` if your backend runs elsewhere.

## Project structure

```text
src/
├── api/             One module per backend resource — the ONLY place
│                    Axios is used directly. Components call these
│                    functions, never axios itself.
│   ├── axios.js            shared Axios instance (baseURL, headers)
│   ├── alertsApi.js
│   ├── analysesApi.js
│   ├── blockedIpsApi.js
│   ├── agentsApi.js
│   ├── simulationApi.js
│   └── dashboardApi.js
│
├── components/
│   ├── alerts/      Alerts table + its row/search/filter/badges
│   ├── blockedIps/  Blocked IP table + its row/search/filter/badges
│   ├── cards/        StatCard (dashboard summary cards)
│   ├── charts/       Recharts-based charts (trend, severity, attack type)
│   ├── common/       Generic building blocks (Panel)
│   ├── details/      Alert-detail sub-panels (info, threat, analysis, etc.)
│   ├── layout/        Navbar, Sidebar, MainLayout (app shell)
│   └── panels/        Dashboard widgets (recent alerts, agent health, etc.)
│
├── constants/        Mock data used until the backend is wired up.
│                      Safe to delete file-by-file once the matching
│                      api/*.js call is used instead.
│
├── hooks/
│   └── useApi.js      Generic { data, loading, error, refetch } hook for
│                       wiring any api/*.js function into a page.
│
├── pages/             One component per route (see routes/router.jsx)
├── routes/
│   └── router.jsx     React Router route table
├── styles/
│   └── global.css     Tailwind v4 import + design tokens (CSS variables)
├── main.jsx           App entry point (renders the router)
```

## Routes

| Path             | Page              |
|------------------|-------------------|
| `/`              | Dashboard         |
| `/alerts`        | Alerts list       |
| `/alerts/:id`    | Alert detail      |
| `/blocked`       | Blocked IPs list  |
| `/blocked/:id`   | Blocked IP detail |
| `/agents`        | Agent monitoring  |
| `/simulation`    | Attack simulation |
| `/settings`      | Settings          |

## Connecting the real backend

Right now every page reads from `src/constants/*.js` (mock data) so the UI
is fully browsable without a backend running. To switch a page to live
data:

1. Import the relevant hook/api function, e.g.
   ```js
   import { useApi } from "../hooks/useApi";
   import { getAlerts } from "../api/alertsApi";
   ```
2. Replace the `import { alertsData } from "../constants/alertsData"` line
   with:
   ```js
   const { data: alertsData, loading, error } = useApi(getAlerts);
   ```
3. Render `loading` / `error` states above the existing table markup.

The `simulationApi.js` call in `pages/Simulation.jsx` is already wired up —
clicking "Generate Attack" will POST to `/simulation/simulate-attack` on
whatever `VITE_API_BASE_URL` points to.

## What was fixed from the original upload

- Restored buildable project scaffolding (`package.json`, `vite.config.js`,
  `index.html`, Tailwind v4 plugin config) — only `src/` was present before.
- `src/hooks` was a stray empty file blocking the real `hooks/` folder from
  existing; replaced with a proper directory containing `useApi.js`.
- Fixed a broken relative import in the Blocked IPs view that referenced
  a non-existent `../components/blockedIps/...` path from inside that same
  folder.
- Moved the full Blocked IPs page implementation out of `components/` (where
  a duplicate, broken copy lived) and into `pages/BlockedIPs.jsx`, which had
  been left as an empty placeholder even though the real component existed.
- Fixed `/blocked-ips` back-link in the Blocked IP detail page to match the
  router's actual `/blocked` path.
- `AlertDetail.jsx` and `BlockedIPDetail.jsx` now read the `:id` route param
  and look up the matching record instead of always displaying the same
  hardcoded sample.
- Removed dead/empty duplicate files: `components/layout/cards/StatCard.jsx`,
  `components/layout/charts/ThreatChart.jsx`, `components/panels/AgentStatus.jsx`,
  and the unused root `App.jsx` (never rendered — `main.jsx` renders the
  router directly).
- Built out the previously empty stub pages — `Agents.jsx`, `Simulation.jsx`,
  `Settings.jsx` — using the existing design language and mock data.
- Added the `api/` layer (`axios.js` + one module per resource) and a
  `useApi` hook per the project spec, so components never call Axios
  directly.
- Made the Sidebar/Navbar responsive with a mobile slide-out menu, and
  fixed a bug where every nav link showed as "active" simultaneously
  (missing `end` prop on the Dashboard `NavLink`).
