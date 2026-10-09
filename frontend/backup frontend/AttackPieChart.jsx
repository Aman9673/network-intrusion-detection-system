import React, { useEffect, useState } from "react";

import {
  Box,
  Paper,
  Typography,
  CircularProgress,
} from "@mui/material";

import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";


const API_URL = "http://127.0.0.1:8000";


// ============================================================
// EXACT CLASSES SUPPORTED BY YOUR CURRENT NIDS MODEL
// ============================================================

const MODEL_CLASSES = [
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


// ============================================================
// COLORS
// ============================================================

const COLORS = [
  "#22c55e",
  "#f97316",
  "#ef4444",
  "#a855f7",
  "#06b6d4",
  "#3b82f6",
  "#ec4899",
  "#eab308",
  "#14b8a6",
  "#f43f5e",
  "#8b5cf6",
];


// ============================================================
// NORMALIZE CLASS NAME
// ============================================================

const normalizeName = (name) => {

  return String(name || "")
    .trim()
    .toLowerCase();

};


// ============================================================
// ATTACK DISTRIBUTION
// ============================================================

function AttackPieChart() {

  const [data, setData] = useState([]);

  const [loading, setLoading] =
    useState(true);


  // ==========================================================
  // FETCH DATA
  // ==========================================================

  const fetchData = async () => {

    try {

      const response = await fetch(
        `${API_URL}/attack-distribution`
      );


      if (!response.ok) {

        throw new Error(
          `HTTP ${response.status}`
        );

      }


      const result =
        await response.json();


      const apiData =
        Array.isArray(result)
          ? result
          : [];


      // ------------------------------------------------------
      // KEEP ONLY CLASSES FROM CURRENT MODEL
      // ------------------------------------------------------

      const filteredData =
        apiData.filter((item) => {

          const name =
            normalizeName(
              item.name
            );

          return MODEL_CLASSES.some(
            modelClass =>
              normalizeName(
                modelClass
              ) === name
          );

        });


      // ------------------------------------------------------
      // SORT ACCORDING TO MODEL CLASS ORDER
      // ------------------------------------------------------

      filteredData.sort(
        (a, b) => {

          const indexA =
            MODEL_CLASSES.findIndex(
              className =>
                normalizeName(
                  className
                ) ===
                normalizeName(
                  a.name
                )
            );


          const indexB =
            MODEL_CLASSES.findIndex(
              className =>
                normalizeName(
                  className
                ) ===
                normalizeName(
                  b.name
                )
            );


          return indexA - indexB;

        }
      );


      setData(
        filteredData
      );


    } catch (error) {

      console.error(
        "Attack distribution error:",
        error
      );


      setData([]);

    } finally {

      setLoading(false);

    }

  };


  // ==========================================================
  // AUTO REFRESH
  // ==========================================================

  useEffect(() => {

    fetchData();


    const interval =
      setInterval(
        fetchData,
        5000
      );


    return () => {

      clearInterval(
        interval
      );

    };

  }, []);


  // ==========================================================
  // RENDER
  // ==========================================================

  return (

    <Paper
      sx={{
        p: 3,

        background:
          "#07101f",

        border:
          "1px solid #1e293b",

        borderRadius: 3,

        color: "white",

        minHeight: 420,

        position: "relative",

        overflow: "hidden",
      }}
    >

      {/* ====================================================
          HEADER
          ==================================================== */}

      <Box
        sx={{
          display: "flex",
          justifyContent:
            "space-between",

          alignItems: "center",

          mb: 0.5,
        }}
      >

        <Typography
          variant="h6"
          sx={{
            fontWeight: 800,

            fontSize: 15,

            letterSpacing:
              "0.7px",

            textTransform:
              "uppercase",
          }}
        >
          Attack Distribution
        </Typography>


        <Typography
          sx={{
            color: "#475569",

            fontSize: 10,

            letterSpacing:
              "0.8px",

            textTransform:
              "uppercase",
          }}
        >
          Model Classes
        </Typography>

      </Box>


      <Typography
        sx={{
          color: "#64748b",

          fontSize: 12,

          mb: 1,
        }}
      >
        Detected threats from live network traffic
      </Typography>


      {/* ====================================================
          LOADING
          ==================================================== */}

      {loading ? (

        <Box
          sx={{
            height: 320,

            display: "flex",

            alignItems:
              "center",

            justifyContent:
              "center",
          }}
        >

          <CircularProgress
            size={30}
            sx={{
              color:
                "#00d9ff",
            }}
          />

        </Box>

      ) : data.length === 0 ? (

        /* ==================================================
           EMPTY
           ================================================== */

        <Box
          sx={{
            height: 320,

            display: "flex",

            flexDirection:
              "column",

            alignItems:
              "center",

            justifyContent:
              "center",

            color: "#64748b",
          }}
        >

          <Typography
            sx={{
              fontSize: 14,
            }}
          >
            No attacks detected yet.
          </Typography>


          <Typography
            sx={{
              mt: 1,

              fontSize: 11,

              color: "#475569",
            }}
          >
            Monitoring 11 supported classes
          </Typography>

        </Box>

      ) : (

        /* ==================================================
           CHART
           ================================================== */

        <Box
          sx={{
            position:
              "relative",

            width:
              "100%",

            height: 330,
          }}
        >

          <ResponsiveContainer
            width="100%"
            height="100%"
          >

            <PieChart>

              <Pie
                data={data}

                dataKey="value"

                nameKey="name"

                cx="50%"

                cy="44%"

                outerRadius={105}

                innerRadius={62}

                paddingAngle={2}

                stroke="#07101f"

                strokeWidth={2}

                label={({ percent }) =>
                  percent >= 0.03
                    ? `${(
                        percent * 100
                      ).toFixed(0)}%`
                    : ""
                }

                labelLine={false}
              >

                {data.map(
                  (entry, index) => (

                    <Cell
                      key={
                        `cell-${index}`
                      }

                      fill={
                        COLORS[
                          index %
                          COLORS.length
                        ]
                      }
                    />

                  )
                )}

              </Pie>


              {/* =================================================
                  TOOLTIP
                  ================================================= */}

              <Tooltip
                contentStyle={{
                  background:
                    "#0f172a",

                  border:
                    "1px solid #334155",

                  borderRadius:
                    8,

                  color:
                    "#ffffff",

                  fontSize:
                    12,
                }}

                labelStyle={{
                  color:
                    "#ffffff",
                }}

                formatter={
                  (value) => [
                    value,
                    "Detections",
                  ]
                }
              />


              {/* =================================================
                  LEGEND
                  ================================================= */}

              <Legend
                verticalAlign="bottom"

                align="center"

                layout="horizontal"

                wrapperStyle={{
                  fontSize: 10,

                  color:
                    "#94a3b8",

                  paddingTop:
                    5,
                }}
              />

            </PieChart>

          </ResponsiveContainer>


          {/* ==================================================
              CENTER LABEL
              ================================================== */}

          <Box
            sx={{
              position:
                "absolute",

              left: "50%",

              top: "44%",

              transform:
                "translate(-50%, -50%)",

              textAlign:
                "center",

              pointerEvents:
                "none",
            }}
          >

            <Typography
              sx={{
                color:
                  "#ffffff",

                fontSize: 27,

                fontWeight: 800,

                lineHeight: 1,
              }}
            >
              11
            </Typography>


            <Typography
              sx={{
                color:
                  "#64748b",

                fontSize: 9,

                letterSpacing:
                  "1px",

                mt: 0.5,
              }}
            >
              CLASSES
            </Typography>

          </Box>

        </Box>

      )}

    </Paper>

  );

}


export default AttackPieChart;