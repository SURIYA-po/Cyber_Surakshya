import {
  createBrowserRouter,
} from "react-router-dom";

import MainLayout from "../components/layout/MainLayout";

import Dashboard from "../pages/Dashboard";
import Alerts from "../pages/Alerts";
import Agents from "../pages/Agents";
import BlockedIPs from "../pages/BlockedIPs";
import Simulation from "../pages/Simulation";
import Settings from "../pages/Settings";
import Memory from "../pages/Memory";
import AlertDetail from "../pages/AlertDetail";
import BlockedIPDetail from "../pages/BlockedIPDetail";
import LiveCapture from "../pages/LiveCapture";
import Response from "../pages/Response";
import Learning from "../pages/Learning";

export const router = createBrowserRouter([
  {
    path: "/",
    element: <MainLayout />,
    children: [
      {
        index: true,
        element: <Dashboard />,
      },
      {
        path: "live",
        element: <LiveCapture />,
      },
      {
        path: "alerts",
        element: <Alerts />,
      },
      {
        path: "response",
        element: <Response />,
      },
      {
        path: "learning",
        element: <Learning />,
      },
      {
        path: "agents",
        element: <Agents />,
      },
      {
        path: "blocked",
        element: <BlockedIPs />,
      },
      {
        path: "simulation",
        element: <Simulation />,
      },
      {
        path: "memory",
        element: <Memory />,
      },
      {
        path: "settings",
        element: <Settings />,
      },
      {
        path: "alerts/:id",
        element: <AlertDetail />,
      },
      {
        path: "blocked/:id",
        element: <BlockedIPDetail />,
      },
    ],
  },
]);

