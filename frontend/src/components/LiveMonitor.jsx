import React, { useEffect, useMemo, useState } from "react";

import {
  Box,
  Paper,
  Typography,
  Chip,
  IconButton,
} from "@mui/material";

import {
  Wifi,
  Security,
  Warning,
  CheckCircle,
  Block,
  Refresh,
  Speed,
  BugReport,
  Router,
  Public,
} from "@mui/icons-material";

import API from "../services/api";


function LiveMonitor() {

  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [lastUpdate, setLastUpdate] = useState(null);


  // =====================================================
  // FETCH LIVE DETECTION LOGS
  // =====================================================

  const fetchEvents = async () => {

    try {

      const response = await API.get("/logs");

      const data = Array.isArray(response.data)
        ? response.data
        : [];

      setEvents(data.slice(0, 30));

      setLastUpdate(new Date());

    } catch (error) {

      console.error(
        "Live monitor error:",
        error
      );

    } finally {

      setLoading(false);

    }

  };


  // =====================================================
  // AUTO REFRESH
  // =====================================================

  useEffect(() => {

    fetchEvents();

    const interval = setInterval(
      fetchEvents,
      2000
    );

    return () => {
      clearInterval(interval);
    };

  }, []);


  // =====================================================
  // STATISTICS
  // =====================================================

  const statistics = useMemo(() => {

    const threats = events.filter(
      event =>
        String(
          event.attack_type || ""
        ).toLowerCase() !== "benign"
    );

    const benign = events.filter(
      event =>
        String(
          event.attack_type || ""
        ).toLowerCase() === "benign"
    );

    const critical = threats.filter(
      event =>
        Number(
          event.confidence || 0
        ) >= 95
    );

    const averageConfidence =
      threats.length > 0
        ? threats.reduce(
            (sum, event) =>
              sum +
              Number(
                event.confidence || 0
              ),
            0
          ) / threats.length
        : 0;

    return {
      total: events.length,
      threats: threats.length,
      benign: benign.length,
      critical: critical.length,
      averageConfidence,
    };

  }, [events]);


  // =====================================================
  // SEVERITY
  // =====================================================

  const getSeverity = (
    confidence,
    attackType
  ) => {

    if (
      String(
        attackType || ""
      ).toLowerCase() === "benign"
    ) {
      return "BENIGN";
    }

    const value = Number(
      confidence || 0
    );

    if (value >= 95) {
      return "CRITICAL";
    }

    if (value >= 80) {
      return "HIGH";
    }

    if (value >= 60) {
      return "MEDIUM";
    }

    return "LOW";
  };


  // =====================================================
  // SEVERITY CLASS
  // =====================================================

  const severityClass = severity => {

    switch (severity) {

      case "CRITICAL":
        return "severity-critical";

      case "HIGH":
        return "severity-high";

      case "MEDIUM":
        return "severity-medium";

      case "LOW":
        return "severity-low";

      default:
        return "severity-benign";

    }

  };


  // =====================================================
  // ACTION ICON
  // =====================================================

  const getActionIcon = (
    action,
    attackType
  ) => {

    if (
      String(
        attackType || ""
      ).toLowerCase() === "benign"
    ) {
      return <CheckCircle />;
    }

    if (
      String(
        action || ""
      ).toLowerCase().includes("block")
    ) {
      return <Block />;
    }

    return <Warning />;

  };


  // =====================================================
  // FORMAT TIME
  // =====================================================

  const formatTime = timestamp => {

    if (!timestamp) {
      return "--:--:--";
    }

    try {

      const date = new Date(timestamp);

      if (
        Number.isNaN(
          date.getTime()
        )
      ) {
        return String(timestamp);
      }

      return date.toLocaleTimeString(
        [],
        {
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
        }
      );

    } catch {

      return String(timestamp);

    }

  };


  // =====================================================
  // RENDER
  // =====================================================

  return (

    <Box className="live-monitor-page">

      {/* =================================================
          HEADER
          ================================================= */}

      <Box className="live-header">

        <Box>

          <Box className="live-title-row">

            <Box className="live-title-pulse" />

            <Typography className="live-title">
              LIVE MONITOR
            </Typography>

          </Box>

          <Typography className="live-subtitle">
            REAL-TIME NETWORK TRAFFIC
            {" "}
            & AI THREAT DETECTION
          </Typography>

        </Box>


        <Box className="live-header-controls">

          <Box className="capture-status">

            <span />

            PACKET CAPTURE ACTIVE

          </Box>


          <Chip
            icon={<Wifi />}
            label="LIVE"
            className="live-chip"
          />


          <IconButton
            onClick={fetchEvents}
            className="live-refresh"
          >
            <Refresh />
          </IconButton>

        </Box>

      </Box>


      {/* =================================================
          TOP METRICS
          ================================================= */}

      <Box className="live-metrics-grid">

        <LiveMetric
          icon={<Speed />}
          title="PACKETS OBSERVED"
          value={statistics.total}
          color="#00d9ff"
        />


        <LiveMetric
          icon={<BugReport />}
          title="THREATS DETECTED"
          value={statistics.threats}
          color="#ff315c"
        />


        <LiveMetric
          icon={<Warning />}
          title="CRITICAL EVENTS"
          value={statistics.critical}
          color="#ff9f1c"
        />


        <LiveMetric
          icon={<Security />}
          title="AVG CONFIDENCE"
          value={
            `${statistics.averageConfidence.toFixed(1)}%`
          }
          color="#b64cff"
        />

      </Box>


      {/* =================================================
          MAIN AREA
          ================================================= */}

      <Box className="live-main-grid">


        {/* =================================================
            PACKET ACTIVITY
            ================================================= */}

        <Paper className="live-panel packet-panel">

          <Box className="live-panel-header">

            <Box className="live-panel-title">

              <Box className="live-panel-icon">
                <Router />
              </Box>

              <Box>

                <Typography>
                  LIVE PACKET ACTIVITY
                </Typography>

                <small>
                  AI INSPECTION STREAM
                </small>

              </Box>

            </Box>


            <Box className="stream-status">

              <span />

              STREAMING

            </Box>

          </Box>


          {/* TABLE HEADER */}

          <Box className="packet-table-header">

            <span>TIME</span>

            <span>SOURCE</span>

            <span>DESTINATION</span>

            <span>DETECTION</span>

            <span>CONF.</span>

            <span>STATUS</span>

          </Box>


          {/* PACKET ROWS */}

          <Box className="packet-list">

            {loading ? (

              <Box className="live-empty">

                INITIALIZING PACKET STREAM...

              </Box>

            ) : events.length === 0 ? (

              <Box className="live-empty">

                <Wifi />

                <span>
                  WAITING FOR NETWORK TRAFFIC
                </span>

                <small>
                  Start packet capture to see
                  live detections
                </small>

              </Box>

            ) : (

              events.map(
                (event, index) => {

                  const attackType =
                    event.attack_type ||
                    "Unknown";


                  const confidence =
                    Number(
                      event.confidence || 0
                    );


                  const severity =
                    getSeverity(
                      confidence,
                      attackType
                    );


                  return (

                    <Box
                      key={
                        event.id ??
                        `${index}-${event.timestamp}`
                      }
                      className="packet-row"
                    >

                      {/* TIME */}

                      <span className="packet-time">

                        {
                          formatTime(
                            event.timestamp
                          )
                        }

                      </span>


                      {/* SOURCE */}

                      <span className="packet-ip">

                        {
                          event.source_ip ||
                          "-"
                        }

                      </span>


                      {/* DESTINATION */}

                      <span className="packet-ip">

                        {
                          event.destination_ip ||
                          "-"
                        }

                      </span>


                      {/* DETECTION */}

                      <span
                        className={
                          `packet-detection ${severityClass(
                            severity
                          )}`
                        }
                      >

                        <span className="detection-dot" />

                        {attackType}

                      </span>


                      {/* CONFIDENCE */}

                      <span className="packet-confidence">

                        {confidence.toFixed(1)}%

                      </span>


                      {/* ACTION */}

                      <span
                        className={
                          `packet-action ${severityClass(
                            severity
                          )}`
                        }
                      >

                        <span className="action-icon">

                          {
                            getActionIcon(
                              event.action,
                              attackType
                            )
                          }

                        </span>

                        {
                          event.action ||
                          "Monitor"
                        }

                      </span>

                    </Box>

                  );

                }
              )

            )}

          </Box>

        </Paper>


        {/* =================================================
            THREAT RADAR
            ================================================= */}

        <Paper className="live-panel radar-panel">

          <Box className="live-panel-header">

            <Box className="live-panel-title">

              <Box className="live-panel-icon">
                <Public />
              </Box>

              <Box>

                <Typography>
                  THREAT RADAR
                </Typography>

                <small>
                  REAL-TIME DETECTION
                </small>

              </Box>

            </Box>

          </Box>


          <Box className="live-radar">

            <div className="radar-circle radar-one" />

            <div className="radar-circle radar-two" />

            <div className="radar-circle radar-three" />

            <div className="radar-cross horizontal" />

            <div className="radar-cross vertical" />

            <div className="radar-line" />


            <div className="radar-center">

              <Security />

              <strong>
                AI
              </strong>

              <small>
                ACTIVE
              </small>

            </div>


            <div className="radar-threat rt-1">
              <span />
            </div>

            <div className="radar-threat rt-2">
              <span />
            </div>

            <div className="radar-threat rt-3">
              <span />
            </div>

            <div className="radar-threat rt-4">
              <span />
            </div>

          </Box>


          <Box className="radar-legend">

            <Box>
              <span className="legend-red" />
              THREAT
            </Box>

            <Box>
              <span className="legend-green" />
              BENIGN
            </Box>

            <Box>
              <span className="legend-cyan" />
              AI CORE
            </Box>

          </Box>

        </Paper>

      </Box>


      {/* =================================================
          FOOTER STATUS
          ================================================= */}

      <Box className="live-footer">

        <Box>

          <span className="footer-live-dot" />

          DETECTION ENGINE ACTIVE

        </Box>


        <Box>
          CNN + RFNN
        </Box>


        <Box>
          78 FEATURES
        </Box>


        <Box>
          11 CLASSES
        </Box>


        <Box>

          LAST UPDATE:

          {" "}

          {
            lastUpdate
              ? lastUpdate.toLocaleTimeString()
              : "--:--:--"
          }

        </Box>

      </Box>

    </Box>

  );

}


// =========================================================
// LIVE METRIC
// =========================================================

function LiveMetric({
  icon,
  title,
  value,
  color,
}) {

  return (

    <Paper
      className="live-metric"
      sx={{
        "--metric-color": color,
      }}
    >

      <Box className="live-metric-icon">

        {icon}

      </Box>


      <Box>

        <span>
          {title}
        </span>

        <strong>
          {value}
        </strong>

      </Box>

    </Paper>

  );

}


export default LiveMonitor;