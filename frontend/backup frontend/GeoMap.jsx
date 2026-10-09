import React, { useEffect, useState } from "react";
import {
  MapContainer,
  TileLayer,
  CircleMarker,
  Popup,
  Polyline,
  useMap,
} from "react-leaflet";
import "leaflet/dist/leaflet.css";
import "../styles/GeoMap.css";

const API_URL = "http://127.0.0.1:8000";

function MapResize() {
  const map = useMap();

  useEffect(() => {
    setTimeout(() => {
      map.invalidateSize();
    }, 200);
  }, [map]);

  return null;
}

function getThreatColor(confidence) {
  if (confidence >= 95) return "#ff1744";
  if (confidence >= 80) return "#ff9100";
  if (confidence >= 60) return "#d500f9";
  return "#00e5ff";
}

function getSeverity(confidence) {
  if (confidence >= 95) return "CRITICAL";
  if (confidence >= 80) return "HIGH";
  if (confidence >= 60) return "MEDIUM";
  return "LOW";
}

export default function GeoMap() {
  const [threats, setThreats] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const loadThreatMap = async () => {
    try {
      const response = await fetch(`${API_URL}/threat-map`);

      if (!response.ok) {
        throw new Error("Failed to load threat map");
      }

      const data = await response.json();

      setThreats(Array.isArray(data) ? data : []);
      setError("");
    } catch (err) {
      console.error("GeoMap error:", err);
      setError("Unable to load threat locations");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadThreatMap();

    const interval = setInterval(loadThreatMap, 10000);

    return () => clearInterval(interval);
  }, []);

  const center = [20, 0];

  return (
    <div className="geo-map-panel">

      <div className="geo-map-header">
        <div>
          <div className="geo-map-title">
            GLOBAL THREAT NETWORK
          </div>

          <div className="geo-map-subtitle">
            LIVE IP GEOLOCATION & ATTACK SOURCES
          </div>
        </div>

        <div className="geo-map-status">
          <span className="status-dot"></span>
          LIVE
        </div>
      </div>

      <div className="geo-map-content">

        {loading ? (
          <div className="geo-map-loading">
            <div className="loading-ring"></div>
            <span>LOADING THREAT LOCATIONS...</span>
          </div>
        ) : error ? (
          <div className="geo-map-error">
            {error}
          </div>
        ) : (
          <MapContainer
            center={center}
            zoom={2}
            minZoom={2}
            maxZoom={8}
            scrollWheelZoom={true}
            className="threat-map"
          >

            <MapResize />

            <TileLayer
              attribution='&copy; OpenStreetMap contributors'
              url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
            />

            {threats.map((threat, index) => {

              if (
                typeof threat.latitude !== "number" ||
                typeof threat.longitude !== "number"
              ) {
                return null;
              }

              const color = getThreatColor(
                Number(threat.max_confidence || 0)
              );

              const severity = getSeverity(
                Number(threat.max_confidence || 0)
              );

              const position = [
                threat.latitude,
                threat.longitude,
              ];

              return (
                <React.Fragment key={`${threat.source_ip}-${index}`}>

                  <CircleMarker
                    center={position}
                    radius={9}
                    pathOptions={{
                      color,
                      fillColor: color,
                      fillOpacity: 0.85,
                      weight: 2,
                    }}
                  >

                    <Popup>
                      <div className="threat-popup">

                        <div className="popup-title">
                          THREAT SOURCE
                        </div>

                        <div className="popup-ip">
                          {threat.source_ip}
                        </div>

                        <div className="popup-line">
                          <strong>LOCATION:</strong>{" "}
                          {threat.city || "Unknown"},{" "}
                          {threat.country || "Unknown"}
                        </div>

                        <div className="popup-line">
                          <strong>ATTACK:</strong>{" "}
                          {threat.attack_type || "Unknown"}
                        </div>

                        <div className="popup-line">
                          <strong>CONFIDENCE:</strong>{" "}
                          {Number(threat.max_confidence || 0).toFixed(2)}%
                        </div>

                        <div className="popup-line">
                          <strong>ATTACKS:</strong>{" "}
                          {threat.attack_count || 0}
                        </div>

                        <div className="popup-severity">
                          {severity}
                        </div>

                      </div>
                    </Popup>

                  </CircleMarker>

                  <Polyline
                    positions={[
                      [20, 78],
                      position,
                    ]}
                    pathOptions={{
                      color,
                      weight: 1,
                      opacity: 0.35,
                      dashArray: "5 8",
                    }}
                  />

                </React.Fragment>
              );
            })}

          </MapContainer>
        )}

        <div className="map-overlay top-left">
          <span>THREAT SOURCES</span>
          <strong>{threats.length}</strong>
        </div>

        <div className="map-overlay bottom-left">
          <span>GEOLOCATION ENGINE</span>
          <strong>GEOLITE2</strong>
        </div>

      </div>

      <div className="geo-map-footer">

        <div>
          <span className="legend critical"></span>
          CRITICAL
        </div>

        <div>
          <span className="legend high"></span>
          HIGH
        </div>

        <div>
          <span className="legend medium"></span>
          MEDIUM
        </div>

        <div>
          <span className="legend low"></span>
          LOW
        </div>

        <div className="geo-refresh">
          AUTO REFRESH: 10s
        </div>

      </div>

    </div>
  );
}