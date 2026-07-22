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
import AlertDetail from "../pages/AlertDetail";
import BlockedIPDetail from "../pages/BlockedIPDetail";

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
        path: "alerts",
        element: <Alerts />,
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

