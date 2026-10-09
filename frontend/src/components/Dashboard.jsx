import React, { useEffect, useMemo, useState } from "react";
import {
  AreaChart,
  Area,
  ResponsiveContainer,
  Tooltip,
  PieChart,
  Pie,
  Cell,
} from "recharts";

import {
  Activity,
  AlertTriangle,
  Ban,
  Bot,
  BrainCircuit,
  CheckCircle2,
  Network,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Zap,
} from "lucide-react";

const API_BASE = "http://127.0.0.1:8000";

/* =========================================================
   ACTUAL NIDS MODEL INFORMATION
   ========================================================= */

const MODEL = {
  name: "Hybrid CNN + RFNN",

  accuracy: 91.19,
  precision: 91.78,
  recall: 88.78,
  macroF1: 89.00,
  weightedF1: 90.44,

  features: 78,
  classes: 11,

  trainSamples: 2081617,
  validationSamples: 446061,
  testSamples: 446061,

  dataset: "CSE-CIC-IDS2018",
  mode: "Detection Only",
};

/* =========================================================
   EXACT 11 MODEL CLASSES
   ========================================================= */

const VALID_CLASSES = [
  "Benign",
  "Bot",
  "DDOS attack-HOIC",
  "DDoS attacks-LOIC-HTTP",
  "DoS attacks-GoldenEye",
  "DoS attacks-Hulk",
  "DoS attacks-SlowHTTPTest",
  "DoS attacks-Slowloris",
  "FTP-BruteForce",
  "Infilteration",
  "SSH-Bruteforce",
];

/* =========================================================
   CLASSIFICATION REPORT
   ========================================================= */

const CLASS_REPORT = [
  ["Benign", 0.9903, 0.9945, 0.9924, 2008333],
  ["Bot", 0.9950, 0.9988, 0.9969, 43313],
  ["DDOS attack-HOIC", 1.0000, 1.0000, 1.0000, 103057],
  ["DDoS attacks-LOIC-HTTP", 0.9857, 0.9955, 0.9906, 86260],
  ["DoS attacks-GoldenEye", 0.9798, 0.9957, 0.9877, 6226],
  ["DoS attacks-Hulk", 0.9995, 0.9995, 0.9995, 69277],
  ["DoS attacks-SlowHTTPTest", 0.7515, 0.4208, 0.5395, 21249],
  ["DoS attacks-Slowloris", 0.8007, 0.9728, 0.8784, 1656],
  ["FTP-BruteForce", 0.6793, 0.8987, 0.7737, 29064],
  ["Infilteration", 0.3494, 0.2029, 0.2567, 24024],
  ["SSH-Bruteforce", 0.9986, 0.9999, 0.9992, 28239],
];

/* =========================================================
   ATTACK COLORS
   ========================================================= */

const ATTACK_COLORS = [
  "#22d3ee",
  "#38bdf8",
  "#60a5fa",
  "#818cf8",
  "#a78bfa",
  "#f472b6",
  "#fb7185",
  "#f97316",
  "#ef4444",
  "#f59e0b",
  "#22c55e",
];

/* =========================================================
   HELPERS
   ========================================================= */

function pct(value) {
  return `${Number(value || 0).toFixed(1)}%`;
}

function StatCard({
  icon: Icon,
  label,
  value,
  sub,
  tone = "cyan",
}) {
  return (
    <div className={`stat-card ${tone}`}>
      <div className="stat-icon">
        <Icon size={21} />
      </div>

      <div>
        <div className="stat-label">{label}</div>

        <div className="stat-value">
          {value}
        </div>

        {sub && (
          <div className="stat-sub">
            {sub}
          </div>
        )}
      </div>
    </div>
  );
}

/* =========================================================
   DASHBOARD
   ========================================================= */

export default function Dashboard() {
  const [dashboard, setDashboard] = useState({});
  const [traffic, setTraffic] = useState([]);
  const [distribution, setDistribution] = useState([]);
  const [threatIps, setThreatIps] = useState([]);
  const [logs, setLogs] = useState([]);

  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState(new Date());
  const [error, setError] = useState("");

  /* =======================================================
     LOAD DASHBOARD DATA
     ======================================================= */

  const loadDashboard = async () => {
    try {
      setError("");

      const results = await Promise.all([
        fetch(`${API_BASE}/dashboard`).then((r) => r.json()),
        fetch(`${API_BASE}/traffic-history`).then((r) => r.json()),
        fetch(`${API_BASE}/attack-distribution`).then((r) => r.json()),
        fetch(`${API_BASE}/threat-ips`).then((r) => r.json()),
        fetch(`${API_BASE}/logs`).then((r) => r.json()),
      ]);

      setDashboard(results[0] || {});

      setTraffic(
        Array.isArray(results[1])
          ? results[1]
          : []
      );

      setDistribution(
        Array.isArray(results[2])
          ? results[2]
          : []
      );

      setThreatIps(
        Array.isArray(results[3])
          ? results[3]
          : []
      );

      setLogs(
        Array.isArray(results[4])
          ? results[4]
          : []
      );

      setLastUpdated(new Date());

    } catch (err) {
      console.error(err);

      setError(
        "Backend connection failed. Make sure FastAPI is running on port 8000."
      );

    } finally {
      setLoading(false);
    }
  };

  /* =======================================================
     AUTO REFRESH
     ======================================================= */

  useEffect(() => {
    loadDashboard();

    const timer = setInterval(
      loadDashboard,
      10000
    );

    return () => clearInterval(timer);
  }, []);

  /* =======================================================
     RECENT ALERTS
     ======================================================= */

  const recentAlerts = useMemo(() => {
    return logs
      .filter(
        (x) =>
          String(
            x.attack_type || ""
          )
            .toLowerCase() !== "benign"
      )
      .slice(0, 6);
  }, [logs]);

  /* =======================================================
     FILTER ATTACK DISTRIBUTION
     IMPORTANT:
     BACKEND MAY STILL RETURN LEGACY CLASSES.
     ONLY SHOW THE 11 MODEL CLASSES.
     ======================================================= */

  const filteredDistribution = useMemo(() => {
    return distribution.filter((item) =>
      VALID_CLASSES.includes(
        String(item.name || "").trim()
      )
    );
  }, [distribution]);

  /* =======================================================
     DASHBOARD NUMBERS
     ======================================================= */

  const totalThreats = Number(
    dashboard.active_threats ??
      dashboard.threats ??
      0
  );

  const totalLogs = Number(
    dashboard.total_logs ??
      logs.length ??
      0
  );

  const totalAlerts = Number(
    dashboard.total_alerts ??
      0
  );

  const backendRiskScore = Number(
    dashboard.risk_score ??
      0
  );

  /* =======================================================
     TRAFFIC
     ======================================================= */

  const computedTrafficBytes = useMemo(() => {
    return logs.reduce(
      (sum, item) =>
        sum + Number(item.bytes || 0),
      0
    );
  }, [logs]);

  const formatBytes = (bytes) => {
    const value = Number(bytes || 0);

    if (value >= 1024 ** 3) {
      return `${(
        value /
        1024 ** 3
      ).toFixed(2)} GB`;
    }

    if (value >= 1024 ** 2) {
      return `${(
        value /
        1024 ** 2
      ).toFixed(2)} MB`;
    }

    if (value >= 1024) {
      return `${(
        value /
        1024
      ).toFixed(2)} KB`;
    }

    return `${value} B`;
  };

  const trafficDisplay =
    dashboard.total_traffic &&
    dashboard.total_traffic !== "0 B"
      ? dashboard.total_traffic
      : formatBytes(
          computedTrafficBytes
        );

  /* =======================================================
     THREATS
     ======================================================= */

  const computedThreats = useMemo(() => {
    return logs.filter(
      (x) =>
        String(
          x.attack_type || ""
        )
          .trim()
          .toLowerCase() !==
        "benign"
    ).length;
  }, [logs]);

  const displayedThreats =
    totalThreats > 0
      ? totalThreats
      : computedThreats;

  const displayedAlerts =
    totalAlerts > 0
      ? totalAlerts
      : computedThreats;

  const riskScore =
    backendRiskScore > 0
      ? backendRiskScore
      : Math.min(
          displayedThreats * 10,
          100
        );

  /* =======================================================
     UI
     ======================================================= */

  return (
    <div className="nids-page">

      <style>{`

        * {
          box-sizing: border-box;
        }

        .nids-page {
          min-height: 100vh;
          padding: 22px;
          color: #dbeafe;

          background:
            radial-gradient(
              circle at 80% 10%,
              rgba(14,165,233,.12),
              transparent 28%
            ),
            radial-gradient(
              circle at 20% 80%,
              rgba(99,102,241,.09),
              transparent 30%
            ),
            #030712;

          font-family:
            Inter,
            ui-sans-serif,
            system-ui,
            -apple-system,
            BlinkMacSystemFont,
            "Segoe UI",
            sans-serif;
        }

        .nids-page::before {
          content: "";
          position: fixed;
          inset: 0;
          pointer-events: none;

          background:
            linear-gradient(
              rgba(34,211,238,.018) 1px,
              transparent 1px
            );

          background-size: 100% 4px;
          z-index: 0;
        }

        .nids-content {
          position: relative;
          z-index: 1;
          max-width: 1700px;
          margin: auto;
        }

        .top-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          gap: 20px;

          padding: 18px 22px;

          border: 1px solid rgba(56,189,248,.22);
          border-radius: 16px;

          background: rgba(7,15,31,.82);

          box-shadow:
            0 0 35px rgba(14,165,233,.08),
            inset 0 0 30px rgba(14,165,233,.025);

          backdrop-filter: blur(16px);
        }

        .brand {
          display: flex;
          align-items: center;
          gap: 14px;
        }

        .brand-icon {
          width: 48px;
          height: 48px;

          display: grid;
          place-items: center;

          border-radius: 13px;

          color: #22d3ee;

          border:
            1px solid
            rgba(34,211,238,.45);

          background:
            rgba(34,211,238,.08);

          box-shadow:
            0 0 22px
            rgba(34,211,238,.15);
        }

        .eyebrow {
          font-size: 11px;
          letter-spacing: 2.5px;
          color: #64748b;
        }

        .title {
          margin-top: 3px;
          font-size: 23px;
          letter-spacing: 1px;
          font-weight: 800;
        }

        .title span {
          color: #22d3ee;
        }

        .header-right {
          display: flex;
          align-items: center;
          gap: 12px;
          flex-wrap: wrap;
          justify-content: flex-end;
        }

        .status-pill {
          display: flex;
          align-items: center;
          gap: 8px;

          padding: 8px 12px;

          border:
            1px solid
            rgba(34,197,94,.3);

          border-radius: 999px;

          color: #86efac;

          background:
            rgba(34,197,94,.07);

          font-size: 12px;
        }

        .dot {
          width: 7px;
          height: 7px;
          border-radius: 50%;

          background: #22c55e;

          box-shadow:
            0 0 10px #22c55e;
        }

        .refresh-btn {
          border:
            1px solid
            rgba(56,189,248,.25);

          background:
            rgba(15,23,42,.8);

          color: #94a3b8;

          border-radius: 10px;

          padding: 9px 11px;

          cursor: pointer;
        }

        .refresh-btn:hover {
          color: #22d3ee;
          border-color: #22d3ee;
        }

        .hero {
          display: flex;
          justify-content: space-between;
          align-items: end;

          gap: 20px;

          padding: 30px 4px 20px;
        }

        .hero h1 {
          margin: 0;
          font-size: 34px;
          color: #f8fafc;
        }

        .hero p {
          margin: 7px 0 0;
          color: #64748b;
          font-size: 13px;
        }

        .hero-meta {
          text-align: right;
          color: #64748b;
          font-size: 12px;
        }

        .grid-5 {
          display: grid;
          grid-template-columns:
            repeat(5, 1fr);

          gap: 14px;
        }

        .stat-card {
          display: flex;
          gap: 14px;
          align-items: center;

          min-height: 105px;
          padding: 17px;

          border:
            1px solid
            rgba(51,65,85,.75);

          border-radius: 14px;

          background:
            linear-gradient(
              145deg,
              rgba(15,23,42,.9),
              rgba(5,12,27,.88)
            );

          box-shadow:
            inset 0 0 25px
            rgba(255,255,255,.015);
        }

        .stat-card.cyan {
          border-color:
            rgba(34,211,238,.22);
        }

        .stat-card.red {
          border-color:
            rgba(239,68,68,.28);
        }

        .stat-card.orange {
          border-color:
            rgba(249,115,22,.28);
        }

        .stat-card.purple {
          border-color:
            rgba(167,139,250,.28);
        }

        .stat-card.green {
          border-color:
            rgba(34,197,94,.28);
        }

        .stat-icon {
          width: 42px;
          height: 42px;
          min-width: 42px;

          display: grid;
          place-items: center;

          border-radius: 11px;

          color: #22d3ee;

          background:
            rgba(34,211,238,.07);
        }

        .red .stat-icon {
          color: #fb7185;
          background:
            rgba(239,68,68,.08);
        }

        .orange .stat-icon {
          color: #fb923c;
          background:
            rgba(249,115,22,.08);
        }

        .purple .stat-icon {
          color: #c4b5fd;
          background:
            rgba(167,139,250,.08);
        }

        .green .stat-icon {
          color: #4ade80;
          background:
            rgba(34,197,94,.08);
        }

        .stat-label {
          font-size: 10px;
          text-transform: uppercase;
          letter-spacing: 1.5px;
          color: #64748b;
        }

        .stat-value {
          margin-top: 4px;
          font-size: 24px;
          font-weight: 800;
          color: #f8fafc;
        }

        .stat-sub {
          margin-top: 3px;
          color: #475569;
          font-size: 10px;
        }

        .section-grid {
          display: grid;
          grid-template-columns: 1fr;
          gap: 16px;
          margin-top: 16px;
        }

        .panel {
          border:
            1px solid
            rgba(51,65,85,.7);

          border-radius: 16px;

          background:
            rgba(7,15,31,.86);

          overflow: hidden;

          box-shadow:
            0 15px 45px
            rgba(0,0,0,.18);
        }

        .panel-head {
          display: flex;
          justify-content: space-between;
          align-items: center;

          padding: 15px 17px;

          border-bottom:
            1px solid
            rgba(51,65,85,.5);
        }

        .panel-title {
          display: flex;
          align-items: center;
          gap: 9px;

          font-size: 12px;
          font-weight: 700;
          letter-spacing: 1.2px;
          text-transform: uppercase;

          color: #cbd5e1;
        }

        .panel-title svg {
          color: #22d3ee;
        }

        .panel-note {
          font-size: 10px;
          color: #475569;
        }

        .panel-body {
          padding: 16px;
        }

        .chart-wrap {
          height: 300px;
        }

        .two-col {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 16px;
          margin-top: 16px;
        }

        .donut-wrap {
          height: 300px;
          position: relative;
        }

        .donut-center {
          position: absolute;
          inset: 0;

          display: flex;
          flex-direction: column;

          align-items: center;
          justify-content: center;

          pointer-events: none;
        }

        .donut-number {
          font-size: 28px;
          font-weight: 800;
          color: #f8fafc;
        }

        .donut-label {
          font-size: 10px;
          color: #64748b;
          text-transform: uppercase;
          letter-spacing: 1px;
        }

        .legend {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 7px 14px;

          max-height: 150px;
          overflow: auto;
        }

        .legend-item {
          display: flex;
          align-items: center;
          gap: 7px;

          color: #94a3b8;
          font-size: 10px;
        }

        .legend-dot {
          width: 7px;
          height: 7px;
          border-radius: 50%;
        }

        .table-wrap {
          overflow: auto;
          max-height: 310px;
        }

        table {
          width: 100%;
          border-collapse: collapse;
          font-size: 11px;
        }

        th {
          position: sticky;
          top: 0;

          background: #08111f;

          color: #475569;

          text-transform: uppercase;
          letter-spacing: 1px;

          font-size: 9px;
          text-align: left;

          padding: 10px;
        }

        td {
          padding: 10px;

          border-top:
            1px solid
            rgba(51,65,85,.3);

          color: #94a3b8;
        }

        tr:hover td {
          background:
            rgba(34,211,238,.025);
        }

        .ip {
          color: #67e8f9;

          font-family:
            ui-monospace,
            SFMono-Regular,
            Menlo,
            monospace;
        }

        .confidence {
          color: #4ade80;
        }

        .attack {
          color: #fb7185;
        }

        .severity {
          display: inline-flex;

          padding: 4px 7px;

          border-radius: 6px;

          font-size: 9px;
          text-transform: uppercase;
          letter-spacing: .7px;

          background:
            rgba(239,68,68,.08);

          color: #fb7185;
        }

        .alert-list {
          display: flex;
          flex-direction: column;
        }

        .alert-row {
          display: grid;
          grid-template-columns:
            auto 1fr auto;

          gap: 11px;

          padding: 12px 0;

          border-bottom:
            1px solid
            rgba(51,65,85,.35);
        }

        .alert-row:last-child {
          border-bottom: 0;
        }

        .alert-icon {
          color: #fb7185;
          margin-top: 2px;
        }

        .alert-main {
          font-size: 11px;
          color: #cbd5e1;
        }

        .alert-time {
          margin-top: 4px;
          font-size: 9px;
          color: #475569;
        }

        .risk-box {
          display: flex;
          align-items: center;
          justify-content: space-between;

          gap: 20px;

          padding: 16px;

          border:
            1px solid
            rgba(239,68,68,.2);

          border-radius: 12px;

          background:
            rgba(239,68,68,.035);

          margin-bottom: 16px;
        }

        .risk-number {
          font-size: 34px;
          font-weight: 900;
          color: #fb7185;
        }

        .risk-label {
          color: #64748b;
          font-size: 10px;
          text-transform: uppercase;
          letter-spacing: 1.5px;
        }

        .bar {
          height: 7px;
          border-radius: 999px;
          background: #111827;
          overflow: hidden;
          flex: 1;
        }

        .bar > div {
          height: 100%;
          border-radius: 999px;

          background:
            linear-gradient(
              90deg,
              #22d3ee,
              #818cf8,
              #fb7185
            );
        }

        .model-panel {
          margin-top: 16px;
        }

        .model-grid {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 16px;
        }

        .model-metrics {
          display: grid;
          grid-template-columns:
            repeat(4, 1fr);

          gap: 10px;
        }

        .metric {
          padding: 14px;

          border:
            1px solid
            rgba(51,65,85,.55);

          border-radius: 11px;

          background:
            rgba(15,23,42,.55);
        }

        .metric-name {
          font-size: 9px;
          text-transform: uppercase;
          letter-spacing: 1px;
          color: #64748b;
        }

        .metric-value {
          margin-top: 7px;
          font-size: 23px;
          font-weight: 800;
          color: #f8fafc;
        }

        .model-info {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 9px;
        }

        .info-box {
          padding: 12px;

          border:
            1px solid
            rgba(51,65,85,.45);

          border-radius: 10px;
        }

        .info-label {
          color: #475569;
          font-size: 9px;
          text-transform: uppercase;
        }

        .info-value {
          margin-top: 4px;
          color: #cbd5e1;
          font-size: 12px;
          font-weight: 600;
        }

        .report-title {
          margin: 0 0 10px;

          color: #cbd5e1;

          font-size: 11px;
          text-transform: uppercase;
          letter-spacing: 1px;
        }

        .cm-placeholder {
          min-height: 320px;

          display: grid;
          place-items: center;

          padding: 15px;

          border:
            1px dashed
            rgba(34,211,238,.18);

          border-radius: 12px;

          background:
            rgba(8,15,30,.5);
        }

        .cm-grid {
          display: grid;

          grid-template-columns:
            repeat(11, minmax(10px,1fr));

          gap: 3px;
          width: 100%;
        }

        .cm-cell {
          aspect-ratio: 1;

          border-radius: 2px;

          background:
            rgba(30,41,59,.65);

          border:
            1px solid
            rgba(51,65,85,.2);
        }

        .cm-cell.diag {
          background:
            rgba(34,211,238,.34);

          border-color:
            rgba(34,211,238,.55);

          box-shadow:
            0 0 7px
            rgba(34,211,238,.18);
        }

        .cm-text {
          position: absolute;

          text-align: center;

          color: #64748b;

          font-size: 10px;

          max-width: 300px;

          line-height: 1.5;
        }

        .footer-status {
          display: flex;
          justify-content: space-between;
          align-items: center;

          gap: 10px;

          margin-top: 16px;
          padding: 12px 15px;

          border-top:
            1px solid
            rgba(51,65,85,.35);

          color: #475569;

          font-size: 10px;
        }

        .online {
          color: #4ade80;
        }

        .empty {
          padding: 35px;

          text-align: center;

          color: #475569;

          font-size: 11px;
        }

        .error {
          margin: 12px 0 0;

          padding: 10px 12px;

          border:
            1px solid
            rgba(239,68,68,.3);

          color: #fca5a5;

          background:
            rgba(239,68,68,.06);

          border-radius: 9px;

          font-size: 11px;
        }

        @media (max-width: 1100px) {

          .grid-5 {
            grid-template-columns:
              repeat(2, 1fr);
          }

          .section-grid,
          .two-col,
          .model-grid {
            grid-template-columns: 1fr;
          }
        }

        @media (max-width: 700px) {

          .nids-page {
            padding: 10px;
          }

          .top-header,
          .hero {
            align-items: flex-start;
            flex-direction: column;
          }

          .hero h1 {
            font-size: 25px;
          }

          .hero-meta {
            text-align: left;
          }

          .grid-5 {
            grid-template-columns: 1fr;
          }

          .model-metrics {
            grid-template-columns: 1fr 1fr;
          }

          .model-info {
            grid-template-columns: 1fr;
          }
        }

      `}</style>

      <div className="nids-content">

        {/* =================================================
            HEADER
            ================================================= */}

        <header className="top-header">

          <div className="brand">

            <div className="brand-icon">
              <ShieldCheck size={26} />
            </div>

            <div>

              <div className="eyebrow">
                AI-POWERED NETWORK SECURITY
              </div>

              <div className="title">
                NIDS{" "}
                <span>
                  COMMAND CENTER
                </span>
              </div>

            </div>

          </div>

          <div className="header-right">

            <div className="status-pill">
              <span className="dot" />
              SYSTEM ONLINE
            </div>

            <div className="panel-note">
              {lastUpdated.toLocaleTimeString()}
            </div>

            <button
              className="refresh-btn"
              onClick={loadDashboard}
              title="Refresh"
            >
              <RefreshCw size={16} />
            </button>

          </div>

        </header>

        {error && (
          <div className="error">
            {error}
          </div>
        )}

        {/* =================================================
            HERO
            ================================================= */}

        <section className="hero">

          <div>

            <h1>
              Network Threat Overview
            </h1>

            <p>
              Real-time intrusion detection,
              traffic intelligence and AI
              model monitoring.
            </p>

          </div>

          <div className="hero-meta">

            DETECTION MODE:{" "}
            <b style={{ color: "#22d3ee" }}>
              ACTIVE
            </b>

            <br />

            AUTO REFRESH: 10 SEC

          </div>

        </section>

        {/* =================================================
            STAT CARDS
            ================================================= */}

        <section className="grid-5">

          <StatCard
            icon={Network}
            label="Total Events"
            value={totalLogs.toLocaleString()}
            sub="Logged network flows"
          />

          <StatCard
            icon={ShieldAlert}
            label="Active Threats"
            value={displayedThreats.toLocaleString()}
            sub="Non-benign events"
            tone="red"
          />

          <StatCard
            icon={AlertTriangle}
            label="Alerts"
            value={displayedAlerts.toLocaleString()}
            sub="Detected threats"
            tone="orange"
          />

          <StatCard
            icon={Activity}
            label="Traffic"
            value={trafficDisplay}
            sub="Cumulative captured traffic"
            tone="purple"
          />

          <StatCard
            icon={BrainCircuit}
            label="AI Accuracy"
            value={pct(MODEL.accuracy)}
            sub={MODEL.name}
            tone="green"
          />

        </section>

        {/* =================================================
            RISK MONITOR
            ================================================= */}

        <section className="section-grid">

          <div className="panel">

            <div className="panel-head">

              <div className="panel-title">
                <Zap size={15} />
                RISK MONITOR
              </div>

              <div className="panel-note">
                CURRENT
              </div>

            </div>

            <div className="panel-body">

              <div className="risk-box">

                <div>

                  <div className="risk-label">
                    Threat Risk Score
                  </div>

                  <div className="risk-number">
                    {riskScore}
                  </div>

                </div>

                <ShieldAlert
                  size={38}
                  color="#fb7185"
                />

              </div>

              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 10,
                  marginBottom: 22,
                }}
              >

                <div className="bar">

                  <div
                    style={{
                      width: `${Math.min(
                        riskScore,
                        100
                      )}%`,
                    }}
                  />

                </div>

                <span
                  style={{
                    fontSize: 10,
                    color: "#64748b",
                  }}
                >
                  {Math.min(
                    riskScore,
                    100
                  )}
                  %
                </span>

              </div>

              <div
                className="panel-title"
                style={{
                  marginBottom: 12,
                }}
              >

                <Activity size={15} />

                RECENT ALERTS

              </div>

              <div className="alert-list">

                {loading && (
                  <div className="empty">
                    Loading alerts...
                  </div>
                )}

                {!loading &&
                  recentAlerts.length === 0 && (
                    <div className="empty">
                      No non-benign alerts found.
                    </div>
                  )}

                {recentAlerts.map(
                  (item, index) => (

                    <div
                      className="alert-row"
                      key={
                        item.id ||
                        index
                      }
                    >

                      <div className="alert-icon">
                        <AlertTriangle
                          size={15}
                        />
                      </div>

                      <div>

                        <div className="alert-main">
                          {item.attack_type ||
                            "Unknown threat"}
                        </div>

                        <div className="alert-time">
                          {item.source_ip ||
                            "Unknown IP"}{" "}
                          •{" "}
                          {item.timestamp ||
                            "—"}
                        </div>

                      </div>

                      <span className="severity">
                        THREAT
                      </span>

                    </div>
                  )
                )}

              </div>

            </div>

          </div>

        </section>

        {/* =================================================
            TRAFFIC + ATTACK DISTRIBUTION
            ================================================= */}

        <section className="two-col">

          {/* NETWORK TRAFFIC */}

          <div className="panel">

            <div className="panel-head">

              <div className="panel-title">
                <Activity size={15} />
                NETWORK TRAFFIC
              </div>

              <div className="panel-note">
                LAST 20 INTERVALS
              </div>

            </div>

            <div className="panel-body">

              <div className="chart-wrap">

                {traffic.length ? (

                  <ResponsiveContainer
                    width="100%"
                    height="100%"
                  >

                    <AreaChart
                      data={traffic}
                    >

                      <defs>

                        <linearGradient
                          id="trafficFill"
                          x1="0"
                          y1="0"
                          x2="0"
                          y2="1"
                        >

                          <stop
                            offset="0%"
                            stopColor="#22d3ee"
                            stopOpacity={0.35}
                          />

                          <stop
                            offset="100%"
                            stopColor="#22d3ee"
                            stopOpacity={0}
                          />

                        </linearGradient>

                      </defs>

                      <Tooltip
                        contentStyle={{
                          background: "#07101f",
                          border:
                            "1px solid #164e63",
                          borderRadius: 8,
                          fontSize: 11,
                        }}

                        labelStyle={{
                          color: "#94a3b8",
                        }}
                      />

                      <Area
                        type="monotone"
                        dataKey="traffic"
                        stroke="#22d3ee"
                        fill="url(#trafficFill)"
                        strokeWidth={2}
                      />

                    </AreaChart>

                  </ResponsiveContainer>

                ) : (

                  <div className="empty">
                    No traffic history available.
                  </div>

                )}

              </div>

            </div>

          </div>

          {/* ATTACK DISTRIBUTION */}

          <div className="panel">

            <div className="panel-head">

              <div className="panel-title">
                <Bot size={15} />
                ATTACK DISTRIBUTION
              </div>

              <div className="panel-note">
                11 MODEL CLASSES
              </div>

            </div>

            <div className="panel-body">

              <div className="donut-wrap">

                {filteredDistribution.length ? (

                  <>

                    <ResponsiveContainer
                      width="100%"
                      height="100%"
                    >

                      <PieChart>

                        <Pie
                          data={
                            filteredDistribution
                          }
                          dataKey="value"
                          nameKey="name"
                          innerRadius={72}
                          outerRadius={108}
                          paddingAngle={2}
                        >

                          {filteredDistribution.map(
                            (_, index) => (

                              <Cell
                                key={index}
                                fill={
                                  ATTACK_COLORS[
                                    index %
                                      ATTACK_COLORS.length
                                  ]
                                }
                              />

                            )
                          )}

                        </Pie>

                        <Tooltip
                          contentStyle={{
                            background:
                              "#07101f",
                            border:
                              "1px solid #164e63",
                            borderRadius: 8,
                            fontSize: 11,
                          }}
                        />

                      </PieChart>

                    </ResponsiveContainer>

                    <div className="donut-center">

                      <div className="donut-number">
                        11
                      </div>

                      <div className="donut-label">
                        Classes
                      </div>

                    </div>

                  </>

                ) : (

                  <div className="empty">
                    No attack distribution available.
                  </div>

                )}

              </div>

              <div className="legend">

                {filteredDistribution.map(
                  (item, index) => (

                    <div
                      className="legend-item"
                      key={
                        item.name ||
                        index
                      }
                    >

                      <span
                        className="legend-dot"
                        style={{
                          background:
                            ATTACK_COLORS[
                              index %
                                ATTACK_COLORS.length
                            ],
                        }}
                      />

                      <span>
                        {item.name}
                      </span>

                    </div>

                  )
                )}

              </div>

            </div>

          </div>

        </section>

        {/* =================================================
            THREAT IPS + ATTACK LOG
            ================================================= */}

        <section className="two-col">

          {/* THREAT IPS */}

          <div className="panel">

            <div className="panel-head">

              <div className="panel-title">
                <Ban size={15} />
                TOP THREAT IPs
              </div>

              <div className="panel-note">
                NON-BENIGN SOURCES
              </div>

            </div>

            <div className="panel-body">

              {threatIps.length ? (

                <div className="table-wrap">

                  <table>

                    <thead>

                      <tr>

                        <th>
                          Source IP
                        </th>

                        <th>
                          Attack Count
                        </th>

                        <th>
                          Max Confidence
                        </th>

                        <th>
                          Last Seen
                        </th>

                      </tr>

                    </thead>

                    <tbody>

                      {threatIps
                        .slice(0, 10)
                        .map(
                          (
                            item,
                            index
                          ) => (

                            <tr
                              key={
                                item.source_ip ||
                                index
                              }
                            >

                              <td className="ip">
                                {item.source_ip ||
                                  "—"}
                              </td>

                              <td>
                                {Number(
                                  item.attack_count ||
                                    0
                                ).toLocaleString()}
                              </td>

                              <td className="confidence">
                                {pct(
                                  item.max_confidence
                                )}
                              </td>

                              <td>
                                {item.last_seen ||
                                  "—"}
                              </td>

                            </tr>

                          )
                        )}

                    </tbody>

                  </table>

                </div>

              ) : (

                <div className="empty">
                  No threat IP data available.
                </div>

              )}

              <div className="footer-status">

                <span>
                  <CheckCircle2
                    size={12}
                    className="online"
                  />{" "}
                  Threat intelligence connected
                </span>

                <span>
                  {threatIps.length} source(s)
                </span>

              </div>

            </div>

          </div>

          {/* ATTACK LOG */}

          <div className="panel">

            <div className="panel-head">

              <div className="panel-title">
                <AlertTriangle size={15} />
                ATTACK LOG
              </div>

              <div className="panel-note">
                LATEST EVENTS
              </div>

            </div>

            <div className="panel-body">

              {logs.length ? (

                <div className="table-wrap">

                  <table>

                    <thead>

                      <tr>

                        <th>
                          Time
                        </th>

                        <th>
                          Source
                        </th>

                        <th>
                          Attack
                        </th>

                        <th>
                          Confidence
                        </th>

                      </tr>

                    </thead>

                    <tbody>

                      {logs
                        .slice(0, 10)
                        .map(
                          (
                            item,
                            index
                          ) => (

                            <tr
                              key={
                                item.id ||
                                index
                              }
                            >

                              <td>
                                {item.timestamp ||
                                  "—"}
                              </td>

                              <td className="ip">
                                {item.source_ip ||
                                  "—"}
                              </td>

                              <td
                                className={
                                  String(
                                    item.attack_type ||
                                      ""
                                  ).toLowerCase() ===
                                  "benign"
                                    ? ""
                                    : "attack"
                                }
                              >
                                {item.attack_type ||
                                  "—"}
                              </td>

                              <td>
                                {item.confidence !=
                                null
                                  ? pct(
                                      item.confidence
                                    )
                                  : "—"}
                              </td>

                            </tr>

                          )
                        )}

                    </tbody>

                  </table>

                </div>

              ) : (

                <div className="empty">
                  No logs available.
                </div>

              )}

            </div>

          </div>

        </section>

        {/* =================================================
            MODEL PERFORMANCE
            ================================================= */}

        <section className="panel model-panel">

          <div className="panel-head">

            <div className="panel-title">

              <BrainCircuit size={16} />

              ML MODEL PERFORMANCE

            </div>

            <div className="panel-note">
              CSE-CIC-IDS2018
            </div>

          </div>

          <div className="panel-body">

            <div className="model-grid">

              {/* MODEL METRICS */}

              <div>

                <div className="model-metrics">

                  <div className="metric">

                    <div className="metric-name">
                      Accuracy
                    </div>

                    <div className="metric-value">
                      {pct(
                        MODEL.accuracy
                      )}
                    </div>

                  </div>

                  <div className="metric">

                    <div className="metric-name">
                      Precision
                    </div>

                    <div className="metric-value">
                      {pct(
                        MODEL.precision
                      )}
                    </div>

                  </div>

                  <div className="metric">

                    <div className="metric-name">
                      Recall
                    </div>

                    <div className="metric-value">
                      {pct(
                        MODEL.recall
                      )}
                    </div>

                  </div>

                  <div className="metric">

                    <div className="metric-name">
                      Macro F1
                    </div>

                    <div className="metric-value">
                      {pct(
                        MODEL.macroF1
                      )}
                    </div>

                  </div>

                </div>

                <div
                  style={{
                    marginTop: 16,
                  }}
                  className="model-info"
                >

                  <div className="info-box">

                    <div className="info-label">
                      Model Architecture
                    </div>

                    <div className="info-value">
                      {MODEL.name}
                    </div>

                  </div>

                  <div className="info-box">

                    <div className="info-label">
                      Dataset
                    </div>

                    <div className="info-value">
                      {MODEL.dataset}
                    </div>

                  </div>

                  <div className="info-box">

                    <div className="info-label">
                      Input Features
                    </div>

                    <div className="info-value">
                      {MODEL.features}
                    </div>

                  </div>

                  <div className="info-box">

                    <div className="info-label">
                      Attack Classes
                    </div>

                    <div className="info-value">
                      {MODEL.classes}
                    </div>

                  </div>

                  <div className="info-box">

                    <div className="info-label">
                      Weighted F1
                    </div>

                    <div className="info-value">
                      {pct(
                        MODEL.weightedF1
                      )}
                    </div>

                  </div>

                  <div className="info-box">

                    <div className="info-label">
                      System Mode
                    </div>

                    <div className="info-value">
                      {MODEL.mode}
                    </div>

                  </div>

                </div>

              </div>

              {/* CONFUSION MATRIX */}

              <div>

                <h3 className="report-title">
                  Confusion Matrix
                </h3>

                <div
                  className="cm-placeholder"
                  style={{
                    position: "relative",
                  }}
                >

                  <div className="cm-grid">

                    {Array.from(
                      {
                        length: 121,
                      },
                      (_, i) => (

                        <div
                          key={i}
                          className={
                            `cm-cell ${
                              i % 12 === 0
                                ? "diag"
                                : ""
                            }`
                          }
                        />

                      )
                    )}

                  </div>

                  <div className="cm-text">

                    Actual confusion-matrix
                    values are not available
                    in the supplied evaluation.

                    <br />

                    This grid is only a
                    visual placeholder —
                    not measured data.

                  </div>

                </div>

              </div>

            </div>

            {/* =================================================
                CLASSIFICATION REPORT
                ================================================= */}

            <div
              style={{
                marginTop: 20,
              }}
            >

              <h3 className="report-title">
                Classification Report
              </h3>

              <div
                className="table-wrap"
                style={{
                  maxHeight: 420,
                }}
              >

                <table>

                  <thead>

                    <tr>

                      <th>
                        Class
                      </th>

                      <th>
                        Precision
                      </th>

                      <th>
                        Recall
                      </th>

                      <th>
                        F1
                      </th>

                      <th>
                        Support
                      </th>

                    </tr>

                  </thead>

                  <tbody>

                    {CLASS_REPORT.map(
                      ([
                        name,
                        precision,
                        recall,
                        f1,
                        support,
                      ]) => (

                        <tr
                          key={name}
                        >

                          <td
                            style={{
                              color:
                                "#cbd5e1",
                            }}
                          >
                            {name}
                          </td>

                          <td>
                            {pct(
                              precision * 100
                            )}
                          </td>

                          <td>
                            {pct(
                              recall * 100
                            )}
                          </td>

                          <td>
                            {pct(
                              f1 * 100
                            )}
                          </td>

                          <td>
                            {support.toLocaleString()}
                          </td>

                        </tr>

                      )
                    )}

                  </tbody>

                </table>

              </div>

            </div>

          </div>

        </section>

        {/* =================================================
            FOOTER
            ================================================= */}

        <div className="footer-status">

          <span className="online">
            ● NIDS ENGINE ONLINE
          </span>

          <span>
            Hybrid CNN + RFNN •
            CSE-CIC-IDS2018 •
            78 Features •
            11 Classes •
            91.19% Accuracy •
            Detection Only
          </span>

          <span>
            Updated{" "}
            {lastUpdated.toLocaleTimeString()}
          </span>

        </div>

      </div>

    </div>
  );
}