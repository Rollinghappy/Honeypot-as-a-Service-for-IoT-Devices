// src/App.js
import React, { useState, useEffect, useRef } from 'react';
import {
  MapPin,
  Activity,
  Shield,
  Settings,
  Clock,
  Terminal,
  Globe,
  PieChart,
  Save,
  Play,
  Square,
  RefreshCw,
  FileText,
  Filter,
  X
} from 'lucide-react';

const API_BASE = 'http://localhost:5000/api';

const PROTOCOLS = ['telnet', 'ssh', 'http', 'mqtt', 'dnp3', 'coap', 'modbus'];

// Mapping for human-readable filter labels
const FIELD_LABELS = {
  // Core Identity
  'ip': 'Source IP Address',
  'port': 'Target Port',
  'protocol': 'Protocol',
  'type': 'Event Type',
  'timestamp': 'Timestamp',
  'username': 'Username',
  'password': 'Password',
  
  // Location
  'location.city': 'City',
  'location.country': 'Country',
  'location.lat': 'Latitude',
  'location.lon': 'Longitude',

  // HTTP / Web
  'method': 'HTTP Method',
  'path': 'Request Path',
  'user_agent': 'User Agent',
  'headers.User-Agent': 'User Agent (Header)',
  'headers.Host': 'Host Header',
  'headers.Content-Type': 'Content Type',
  'headers.Authorization': 'Auth Header',
  
  // Arguments & Payloads
  'args.cmd': 'Command Argument',
  'args.username': 'Username Argument',
  'args.password': 'Password Argument',
  'args.country': 'Country Argument',
  'data.function_code': 'Function Code',
  'data.transaction_id': 'Transaction ID',
  'data.unit_id': 'Unit ID',
  
  // Session
  'session.start': 'Session Start',
  'session.end': 'Session End',
  'session.ip': 'Session IP',
};

// Helper to format unknown keys prettily
const formatFilterLabel = (key) => {
  // 1. Check if we have a direct mapping
  if (FIELD_LABELS[key]) {
    return FIELD_LABELS[key];
  }

  // 2. Fallback: Prettify the dot notation
  // e.g., "headers.Accept-Encoding" -> "Headers › Accept Encoding"
  return key
    .split('.')
    .map((part) => {
      // Replace underscores/dashes with spaces and capitalize
      return part
        .replace(/[-_]/g, ' ')
        .replace(/\b\w/g, (l) => l.toUpperCase());
    })
    .join(' › ');
};

// ---------- DASHBOARD PAGE ----------

const Dashboard = () => {
  const [logs, setLogs] = useState([]);
  const [stats, setStats] = useState({});
  const [selectedAttack, setSelectedAttack] = useState(null);
  const [loading, setLoading] = useState(true);

  // raw log viewer state
  const [rawProtocol, setRawProtocol] = useState('ssh');
  const [rawLogs, setRawLogs] = useState('');
  const [rawLoading, setRawLoading] = useState(false);
  const [rawError, setRawError] = useState(null);

  // filter state
  const [filters, setFilters] = useState({});
  const [showFilters, setShowFilters] = useState(false);
  const [availableFields, setAvailableFields] = useState([]);
  const [fieldProtocols, setFieldProtocols] = useState({}); // New state to track protocols per field

  // --- MAP STATE ---
  const mapImgRef = useRef(null);
  const [mapSize, setMapSize] = useState({ width: 800, height: 400 });

  useEffect(() => {
    fetchDashboardData();
    const interval = setInterval(fetchDashboardData, 10000);
    return () => clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // --- MAP RESIZE LISTENER ---
  useEffect(() => {
    const updateSize = () => {
      try {
        const img = mapImgRef.current;
        if (img) {
          const rect = img.getBoundingClientRect();
          if (rect.width && rect.height) {
            setMapSize({ width: rect.width, height: rect.height });
          }
        }
      } catch (e) {
        // ignore errors if ref is not yet available
      }
    };
    
    window.addEventListener('resize', updateSize);
    // Initial check
    updateSize();
    
    return () => window.removeEventListener('resize', updateSize);
  }, []);

  // Extract all available fields from logs AND track which protocol they belong to
  useEffect(() => {
    const fields = new Set();
    const fieldProtoMap = {}; // Maps 'field.name' -> Set('SSH', 'HTTP')

    logs.forEach((log) => {
      const proto = log.protocol ? log.protocol.toUpperCase() : 'UNKNOWN';

      const extractFields = (obj, prefix = '') => {
        if (obj && typeof obj === 'object' && !Array.isArray(obj)) {
          Object.keys(obj).forEach((key) => {
            const fullKey = prefix ? `${prefix}.${key}` : key;
            if (obj[key] !== null && obj[key] !== undefined) {
              if (typeof obj[key] === 'object' && !Array.isArray(obj[key]) && obj[key] !== null) {
                extractFields(obj[key], fullKey);
              } else {
                fields.add(fullKey);
                
                // Track which protocol this field was seen in
                if (!fieldProtoMap[fullKey]) {
                  fieldProtoMap[fullKey] = new Set();
                }
                fieldProtoMap[fullKey].add(proto);
              }
            }
          });
        }
      };
      extractFields(log);
    });

    setAvailableFields(Array.from(fields).sort());
    setFieldProtocols(fieldProtoMap);
  }, [logs]);

  const fetchDashboardData = async () => {
    try {
      const [logsRes, statsRes] = await Promise.all([
        fetch(`${API_BASE}/logs`),
        fetch(`${API_BASE}/stats`)
      ]);

      const logsData = await logsRes.json();
      const statsData = await statsRes.json();

      setLogs(Array.isArray(logsData) ? logsData : []);
      setStats(statsData || {});
      setLoading(false);
    } catch (error) {
      console.error('Error fetching dashboard data:', error);
      setLoading(false);
    }
  };

  // ---- Raw log viewer ----
  const fetchRawLogs = async (protocol = rawProtocol) => {
    try {
      setRawLoading(true);
      setRawError(null);
      setRawLogs('');

      const res = await fetch(
        `${API_BASE}/raw-logs?protocol=${encodeURIComponent(protocol)}`
      );
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }

      const text = await res.text();
      setRawLogs(text || '(No log data yet)');
    } catch (err) {
      console.error('Error fetching raw logs:', err);
      setRawError('Failed to load raw logs');
    } finally {
      setRawLoading(false);
    }
  };

  const getNestedValue = (obj, path) => {
    return path.split('.').reduce((current, key) => {
      return current && typeof current === 'object' ? current[key] : undefined;
    }, obj);
  };

  const getFilteredLogs = () => {
    if (Object.keys(filters).length === 0) {
      return logs;
    }

    return logs.filter((log) => {
      return Object.entries(filters).every(([field, filterValue]) => {
        if (!filterValue || filterValue.trim() === '') {
          return true;
        }

        const value = getNestedValue(log, field);
        
        if (value === undefined || value === null) {
          return false;
        }

        const valueStr = typeof value === 'object' 
          ? JSON.stringify(value).toLowerCase()
          : String(value).toLowerCase();
        
        const filterStr = filterValue.toLowerCase();
        
        return valueStr.includes(filterStr);
      });
    });
  };

  const handleFilterChange = (field, value) => {
    setFilters((prev) => {
      const newFilters = { ...prev };
      if (value && value.trim() !== '') {
        newFilters[field] = value;
      } else {
        delete newFilters[field];
      }
      return newFilters;
    });
  };

  const clearFilters = () => {
    setFilters({});
  };

  const getLocationMarkers = () => {
    const markers = {};
    const filteredLogs = getFilteredLogs();
    filteredLogs.forEach((log) => {
      if (
        log.ip &&
        log.location &&
        typeof log.location.lat === 'number' &&
        typeof log.location.lon === 'number'
      ) {
        if (!markers[log.ip]) {
          markers[log.ip] = { ...log.location, count: 0, ip: log.ip };
        }
        markers[log.ip].count += 1;
      }
    });
    return Object.values(markers);
  };

  const getProtocolData = () => {
    const protocols = stats.protocolCounts || {};
    return Object.entries(protocols).map(([name, value]) => ({
      name,
      value,
      color: getProtocolColor(name)
    }));
  };

  const getProtocolColor = (protocol) => {
    const colors = {
      telnet: '#D4A574',
      ssh: '#B8956A',
      http: '#9C8560',
      mqtt: '#807556',
      dnp3: '#64654C',
      coap: '#C4B5A0',
      modbus: '#AFA090'
    };
    return colors[protocol?.toLowerCase()] || '#8B8B8B';
  };

  // Helper to map Lat/Lon to X/Y on an Equirectangular map image
  const latLonToXY = (lat, lon, width, height) => {
    const x = ((lon + 180) / 360) * width;
    const y = ((90 - lat) / 180) * height;
    return { x, y };
  };

  const renderWorldMap = () => {
    const markers = getLocationMarkers();
    const imgSrc = '/world-map.svg';

    const containerStyle = {
      position: 'relative',
      width: '100%',
      height: 'auto',
      minHeight: '240px',
      backgroundColor: '#f8f8f8',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center'
    };

    const imgStyle = {
      display: 'block',
      width: '100%',
      height: 'auto',
      userSelect: 'none',
    };

    const overlayStyle = {
      position: 'absolute',
      top: 0,
      left: 0,
      width: '100%',
      height: '100%',
      pointerEvents: 'none'
    };

    const onImgLoad = (e) => {
      try {
        const img = e.target;
        const rect = img.getBoundingClientRect();
        if (rect.width && rect.height) {
          setMapSize({ width: rect.width, height: rect.height });
        }
      } catch (err) {
        // Fallback size if something goes wrong
        setMapSize({ width: 800, height: 400 });
      }
    };

    return (
      <div style={containerStyle} className="rounded-lg overflow-hidden border border-gray-200">
        <img
          ref={mapImgRef}
          src={imgSrc}
          alt="World Map"
          style={imgStyle}
          onLoad={onImgLoad}
          onError={(e) => {
            console.error("Failed to load map image");
            e.target.style.display = 'none'; // Hide broken image icon
          }}
        />
        
        {/* SVG Overlay for attack dots */}
        <svg style={overlayStyle} viewBox={`0 0 ${mapSize.width} ${mapSize.height}`} preserveAspectRatio="none">
          {markers.map((marker, i) => {
            const lat = Number(marker.lat) || 0;
            const lon = Number(marker.lon) || 0;
            const { x, y } = latLonToXY(lat, lon, mapSize.width, mapSize.height);
            const r = Math.min(marker.count * 2 + 5, 18);

            return (
              <g key={marker.ip || i} transform={`translate(${x}, ${y})`}>
                <circle r={r} fill="#D4A574" opacity="0.6" />
                <circle r={Math.max(2, Math.floor(r / 3))} fill="#8B6F47" />
                <title>{`${marker.ip}: ${marker.count} events`}</title>
              </g>
            );
          })}
        </svg>
        
        <div className="absolute bottom-2 left-2 text-xs text-gray-500 bg-white/80 px-2 py-1 rounded shadow-sm">
          <Globe className="w-3 h-3 inline mr-1" />
          Attack Origin Map
        </div>
      </div>
    );
  };

  const renderDonutChart = () => {
    const data = getProtocolData();
    const total = data.reduce((sum, d) => sum + d.value, 0);
    if (total === 0) {
      return <div className="text-sm text-gray-400">No attack data yet.</div>;
    }

    let currentAngle = 0;

    return (
      <svg viewBox="0 0 200 200" className="w-full h-full">
        <circle
          cx="100"
          cy="100"
          r="80"
          fill="none"
          stroke="#F5F5F0"
          strokeWidth="40"
        />
        {data.map((item, i) => {
          const percentage = item.value / total;
          const angle = percentage * 360;
          const startAngle = currentAngle;
          currentAngle += angle;

          const x1 = 100 + 60 * Math.cos(((startAngle - 90) * Math.PI) / 180);
          const y1 = 100 + 60 * Math.sin(((startAngle - 90) * Math.PI) / 180);
          const x2 = 100 + 60 * Math.cos(((currentAngle - 90) * Math.PI) / 180);
          const y2 = 100 + 60 * Math.sin(((currentAngle - 90) * Math.PI) / 180);
          const largeArc = angle > 180 ? 1 : 0;

          return (
            <path
              key={i}
              d={`M 100 100 L ${x1} ${y1} A 60 60 0 ${largeArc} 1 ${x2} ${y2} Z`}
              fill={item.color}
              opacity="0.9"
            />
          );
        })}
        <circle cx="100" cy="100" r="40" fill="white" />
        <text
          x="100"
          y="105"
          textAnchor="middle"
          className="text-2xl font-semibold fill-gray-700"
        >
          {total}
        </text>
      </svg>
    );
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen">
        <RefreshCw className="w-8 h-8 animate-spin text-gray-400" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-white p-4 rounded-lg border border-gray-200">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Total Events</p>
              <p className="text-2xl font-semibold text-gray-800">
                {stats.totalAttacks || 0}
              </p>
            </div>
            <Shield className="w-8 h-8 text-gray-400" />
          </div>
        </div>
        <div className="bg-white p-4 rounded-lg border border-gray-200">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Unique IPs</p>
              <p className="text-2xl font-semibold text-gray-800">
                {stats.uniqueIPs || 0}
              </p>
            </div>
            <MapPin className="w-8 h-8 text-gray-400" />
          </div>
        </div>
        <div className="bg-white p-4 rounded-lg border border-gray-200">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Active Honeypots</p>
              <p className="text-2xl font-semibold text-gray-800">
                {stats.activeHoneypots || 0}
              </p>
            </div>
            <Activity className="w-8 h-8 text-gray-400" />
          </div>
        </div>
        <div className="bg-white p-4 rounded-lg border border-gray-200">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Commands Logged</p>
              <p className="text-2xl font-semibold text-gray-800">
                {stats.commandsLogged || 0}
              </p>
            </div>
            <Terminal className="w-8 h-8 text-gray-400" />
          </div>
        </div>
      </div>

      {/* Main Dashboard Grid */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* World Map */}
        <div className="xl:col-span-2 bg-white p-6 rounded-lg border border-gray-200">
          <h3 className="text-lg font-semibold text-gray-800 mb-4 flex items-center">
            <Globe className="w-5 h-5 mr-2 text-gray-600" />
            Attack Origin Map
          </h3>
          <div className="h-80 flex items-center justify-center bg-gray-50 rounded">
            {renderWorldMap()}
          </div>
        </div>

        {/* Protocol Distribution */}
        <div className="bg-white p-6 rounded-lg border border-gray-200">
          <h3 className="text-lg font-semibold text-gray-800 mb-4 flex items-center">
            <PieChart className="w-5 h-5 mr-2 text-gray-600" />
            Protocol Distribution
          </h3>
          <div className="h-80 flex items-center justify-center">
            {renderDonutChart()}
          </div>
          <div className="mt-4 space-y-2">
            {getProtocolData().map((item, i) => (
              <div key={i} className="flex items-center justify-between text-sm">
                <div className="flex items-center">
                  <div
                    className="w-3 h-3 rounded-full mr-2"
                    style={{ backgroundColor: item.color }}
                  />
                  <span className="text-gray-700 capitalize">{item.name}</span>
                </div>
                <span className="text-gray-600 font-medium">{item.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Timeline + Raw Logs */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Timeline */}
        <div className="xl:col-span-2 bg-white p-6 rounded-lg border border-gray-200">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-gray-800 flex items-center">
              <Clock className="w-5 h-5 mr-2 text-gray-600" />
              Attack / Event Timeline
            </h3>
            <div className="flex items-center space-x-2">
              {Object.keys(filters).length > 0 && (
                <span className="text-xs text-gray-500">
                  {getFilteredLogs().length} of {logs.length} events
                </span>
              )}
              <button
                onClick={() => setShowFilters(!showFilters)}
                className={`flex items-center px-3 py-1.5 text-sm rounded-lg border transition-colors ${
                  showFilters || Object.keys(filters).length > 0
                    ? 'bg-gray-100 border-gray-300 text-gray-800'
                    : 'border-gray-200 text-gray-600 hover:bg-gray-50'
                }`}
              >
                <Filter className="w-4 h-4 mr-1.5" />
                Filters
                {Object.keys(filters).length > 0 && (
                  <span className="ml-1.5 px-1.5 py-0.5 bg-gray-300 rounded text-xs">
                    {Object.keys(filters).length}
                  </span>
                )}
              </button>
              {Object.keys(filters).length > 0 && (
                <button
                  onClick={clearFilters}
                  className="flex items-center px-3 py-1.5 text-sm rounded-lg border border-gray-200 text-gray-600 hover:bg-gray-50"
                  title="Clear all filters"
                >
                  <X className="w-4 h-4" />
                </button>
              )}
            </div>
          </div>

          {/* Filter Panel - MODIFIED SECTION */}
          {showFilters && (
            <div className="mb-4 p-4 bg-gray-50 rounded-lg border border-gray-200">
              <div className="flex items-center justify-between mb-3">
                <h4 className="text-sm font-semibold text-gray-700">Filter Events</h4>
                <button
                  onClick={() => setShowFilters(false)}
                  className="text-gray-400 hover:text-gray-600"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 max-h-64 overflow-y-auto">
                {availableFields.map((field) => {
                  // Generate protocol tags
                  const protos = fieldProtocols[field] ? Array.from(fieldProtocols[field]) : [];
                  const protoLabel = protos.length > 0 && protos.length <= 4
                    ? `(${protos.join(', ')})` 
                    : protos.length > 4 ? '(General)' : '';

                  return (
                    <div key={field} className="flex flex-col">
                      <div className="flex items-baseline mb-1">
                        <label className="text-xs font-medium text-gray-600 mr-2" title={field}>
                          {formatFilterLabel(field)}
                        </label>
                        {protoLabel && (
                          <span className="text-[10px] text-gray-400 font-mono uppercase tracking-tight">
                            {protoLabel}
                          </span>
                        )}
                      </div>
                      <input
                        type="text"
                        value={filters[field] || ''}
                        onChange={(e) => handleFilterChange(field, e.target.value)}
                        placeholder="Filter..."
                        className="px-2 py-1.5 text-sm border border-gray-300 rounded focus:ring-2 focus:ring-gray-400 focus:border-transparent"
                      />
                    </div>
                  );
                })}
              </div>
              {availableFields.length === 0 && (
                <div className="text-sm text-gray-400 text-center py-4">
                  No events available to extract fields from
                </div>
              )}
            </div>
          )}

          <div className="space-y-2 max-h-96 overflow-y-auto">
            {logs.length === 0 && (
              <div className="text-sm text-gray-400">
                No events yet. Once honeypots receive traffic, they&apos;ll show
                up here.
              </div>
            )}
            {getFilteredLogs().slice(0, 100).map((log, i) => (
              <div
                key={log.id || `${log.ip}-${log.timestamp}-${i}`}
                onClick={() => setSelectedAttack(log)}
                className="flex items-center justify-between p-3 hover:bg-gray-50 rounded cursor-pointer border border-gray-100"
              >
                <div className="flex items-center space-x-4">
                  <div className="text-xs text-gray-500 w-40">
                    {log.timestamp
                      ? new Date(log.timestamp).toLocaleString()
                      : '-'}
                  </div>
                  <div className="flex items-center space-x-2">
                    <MapPin className="w-4 h-4 text-gray-400" />
                    <span className="text-sm font-mono text-gray-700">
                      {log.ip || 'unknown'}
                    </span>
                  </div>
                  <span className="text-xs px-2 py-1 rounded bg-gray-100 text-gray-600 capitalize">
                    {log.protocol || 'unknown'}
                  </span>
                  <span className="text-xs px-2 py-1 rounded bg-gray-50 text-gray-500">
                    {log.type || 'event'}
                  </span>
                </div>
                <Terminal className="w-4 h-4 text-gray-400" />
              </div>
            ))}
          </div>
        </div>

        {/* Raw Log Viewer */}
        <div className="bg-white p-6 rounded-lg border border-gray-200">
          <h3 className="text-lg font-semibold text-gray-800 mb-4 flex items-center">
            <FileText className="w-5 h-5 mr-2 text-gray-600" />
            Raw Log Viewer
          </h3>

          <div className="flex items-center mb-3 space-x-2">
            <select
              value={rawProtocol}
              onChange={(e) => {
                const value = e.target.value;
                setRawProtocol(value);
                fetchRawLogs(value);
              }}
              className="flex-1 px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-gray-400 focus:border-transparent"
            >
              {PROTOCOLS.map((p) => (
                <option key={p} value={p}>
                  {p.toUpperCase()}
                </option>
              ))}
            </select>
            <button
              onClick={() => fetchRawLogs()}
              className="px-4 py-2 text-sm bg-gray-800 text-white rounded-lg hover:bg-gray-900 flex items-center"
            >
              {rawLoading ? (
                <>
                  <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                  Loading
                </>
              ) : (
                <>
                  <FileText className="w-4 h-4 mr-2" />
                  Load
                </>
              )}
            </button>
          </div>

          {rawError && (
            <div className="text-xs text-red-500 mb-2">{rawError}</div>
          )}

          <div className="h-64 border border-gray-200 rounded-lg bg-black text-green-300 text-xs overflow-auto p-3 font-mono">
            {rawLogs ? (
              <pre className="whitespace-pre-wrap">{rawLogs}</pre>
            ) : rawLoading ? (
              <div className="text-gray-400">Loading logs...</div>
            ) : (
              <div className="text-gray-500">
                Click &quot;Load&quot; to view contents of{' '}
                <span className="font-semibold">
                  logs/{rawProtocol}.logs
                </span>{' '}
                on the server.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Attack Details Modal */}
      {selectedAttack && (
        <div
          className="fixed inset-0 bg-black bg-opacity-30 flex items-center justify-center p-4 z-50"
          onClick={() => setSelectedAttack(null)}
        >
          <div
            className="bg-white rounded-lg p-6 max-w-3xl w-full max-h-[80vh] overflow-y-auto"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex justify-between items-start mb-4">
              <div>
                <h3 className="text-xl font-semibold text-gray-800">
                  Event / Attack Details
                </h3>
                <p className="text-sm text-gray-500 mt-1">
                  {selectedAttack.ip || 'unknown'} —{' '}
                  {selectedAttack.timestamp
                    ? new Date(selectedAttack.timestamp).toLocaleString()
                    : '-'}
                </p>
              </div>
              <button
                onClick={() => setSelectedAttack(null)}
                className="text-gray-400 hover:text-gray-600 text-2xl leading-none"
              >
                ×
              </button>
            </div>
            <div className="bg-gray-900 text-gray-100 p-4 rounded font-mono text-sm space-y-2">
              <div>
                <span className="text-gray-400">Type: </span>
                {selectedAttack.type || 'event'}
              </div>
              <div>
                <span className="text-gray-400">Protocol: </span>
                {selectedAttack.protocol || 'unknown'}
              </div>
              {selectedAttack.command && (
                <div>
                  <span className="text-gray-400">Command: </span>
                  {selectedAttack.command}
                </div>
              )}
              {selectedAttack.data && (
                <div>
                  <span className="text-gray-400">Data:</span>
                  <pre className="mt-2 text-xs whitespace-pre-wrap">
                    {typeof selectedAttack.data === 'string'
                      ? selectedAttack.data
                      : JSON.stringify(selectedAttack.data, null, 2)}
                  </pre>
                </div>
              )}
              {selectedAttack.raw && (
                <div>
                  <span className="text-gray-400">Raw Log:</span>
                  <pre className="mt-2 text-xs whitespace-pre-wrap">
                    {selectedAttack.raw}
                  </pre>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

// ---------- SETTINGS PAGE ----------

const SettingsPage = () => {
  const [configs, setConfigs] = useState({});
  const [selectedProtocol, setSelectedProtocol] = useState('telnet');
  const [honeypotStatus, setHoneypotStatus] = useState({});
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    fetchConfigs();
    fetchHoneypotStatus();
  }, []);

  const fetchConfigs = async () => {
    try {
      const response = await fetch(`${API_BASE}/configs`);
      const data = await response.json();
      setConfigs(data || {});
    } catch (error) {
      console.error('Error fetching configs:', error);
    }
  };

  const fetchHoneypotStatus = async () => {
    try {
      const response = await fetch(`${API_BASE}/status`);
      const data = await response.json();
      setHoneypotStatus(data || {});
    } catch (error) {
      console.error('Error fetching status:', error);
    }
  };

  const handleConfigChange = (field, value) => {
    setConfigs((prev) => ({
      ...prev,
      [selectedProtocol]: {
        ...prev[selectedProtocol],
        [field]: value
      }
    }));
  };

  const saveConfig = async () => {
    setSaving(true);
    try {
      await fetch(`${API_BASE}/configs/${selectedProtocol}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(configs[selectedProtocol] || {})
      });
      alert('Configuration saved successfully!');
    } catch (error) {
      console.error('Error saving config:', error);
      alert('Error saving configuration');
    }
    setSaving(false);
  };

  const toggleHoneypot = async (protocol) => {
    try {
      const action = honeypotStatus[protocol] ? 'stop' : 'start';
      await fetch(`${API_BASE}/honeypot/${protocol}/${action}`, {
        method: 'POST'
      });
      fetchHoneypotStatus();
    } catch (error) {
      console.error('Error toggling honeypot:', error);
    }
  };

  const currentConfig = configs[selectedProtocol] || {};

  return (
    <div className="space-y-6">
      <div className="bg-white p-6 rounded-lg border border-gray-200">
        <h2 className="text-2xl font-semibold text-gray-800 mb-6">
          Honeypot Settings
        </h2>

        {/* Protocol Selection */}
        <div className="mb-6">
          <h3 className="text-sm font-medium text-gray-700 mb-3">
            Select Protocol
          </h3>
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3">
            {PROTOCOLS.map((protocol) => (
              <button
                key={protocol}
                onClick={() => setSelectedProtocol(protocol)}
                className={`p-3 rounded-lg border-2 transition-all capitalize ${
                  selectedProtocol === protocol
                    ? 'border-gray-400 bg-gray-50'
                    : 'border-gray-200 hover:border-gray-300'
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium text-gray-700">
                    {protocol}
                  </span>
                  <div
                    className={`w-2 h-2 rounded-full ${
                      honeypotStatus[protocol]
                        ? 'bg-green-500'
                        : 'bg-gray-300'
                    }`}
                  />
                </div>
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    toggleHoneypot(protocol);
                  }}
                  className={`w-full py-1 px-2 rounded text-xs ${
                    honeypotStatus[protocol]
                      ? 'bg-red-100 text-red-700 hover:bg-red-200'
                      : 'bg-green-100 text-green-700 hover:bg-green-200'
                  }`}
                >
                  {honeypotStatus[protocol] ? (
                    <>
                      <Square className="w-3 h-3 inline mr-1" />
                      Stop
                    </>
                  ) : (
                    <>
                      <Play className="w-3 h-3 inline mr-1" />
                      Start
                    </>
                  )}
                </button>
              </button>
            ))}
          </div>
        </div>

        {/* Configuration Form */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Basic Settings */}
          <div className="space-y-4">
            <h3 className="text-lg font-semibold text-gray-800 border-b border-gray-200 pb-2">
              Basic Settings
            </h3>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Host
              </label>
              <input
                type="text"
                value={currentConfig.host || '0.0.0.0'}
                onChange={(e) => handleConfigChange('host', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-gray-400 focus:border-transparent"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Port
              </label>
              <input
                type="number"
                value={currentConfig.port || ''}
                onChange={(e) =>
                  handleConfigChange(
                    'port',
                    parseInt(e.target.value, 10) || 0
                  )
                }
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-gray-400 focus:border-transparent"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Hostname
              </label>
              <input
                type="text"
                value={currentConfig.hostname || ''}
                onChange={(e) => handleConfigChange('hostname', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-gray-400 focus:border-transparent"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Banner
              </label>
              <textarea
                value={currentConfig.banner || ''}
                onChange={(e) => handleConfigChange('banner', e.target.value)}
                rows={3}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-gray-400 focus:border-transparent"
              />
            </div>

            <div className="flex items-center">
              <input
                type="checkbox"
                checked={currentConfig.allow_all_logins || false}
                onChange={(e) =>
                  handleConfigChange('allow_all_logins', e.target.checked)
                }
                className="w-4 h-4 text-gray-600 border-gray-300 rounded focus:ring-gray-400"
              />
              <label className="ml-2 text-sm text-gray-700">
                Allow All Logins
              </label>
            </div>
          </div>

          {/* Advanced Settings */}
          <div className="space-y-4">
            <h3 className="text-lg font-semibold text-gray-800 border-b border-gray-200 pb-2">
              Advanced Settings
            </h3>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Valid Credentials
              </label>
              <textarea
                value={JSON.stringify(
                  currentConfig.valid_credentials || {},
                  null,
                  2
                )}
                onChange={(e) => {
                  try {
                    handleConfigChange(
                      'valid_credentials',
                      JSON.parse(e.target.value)
                    );
                  } catch {
                    // ignore JSON errors for now
                  }
                }}
                rows={5}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg font-mono text-sm focus:ring-2 focus:ring-gray-400 focus:border-transparent"
                placeholder='{"username": "password"}'
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Filesystem Structure
              </label>
              <textarea
                value={JSON.stringify(currentConfig.filesystem || {}, null, 2)}
                onChange={(e) => {
                  try {
                    handleConfigChange('filesystem', JSON.parse(e.target.value));
                  } catch {
                    // ignore
                  }
                }}
                rows={6}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg font-mono text-sm focus:ring-2 focus:ring-gray-400 focus:border-transparent"
                placeholder='{"/": ["bin", "etc"]}'
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Custom Files
              </label>
              <textarea
                value={JSON.stringify(currentConfig.files || {}, null, 2)}
                onChange={(e) => {
                  try {
                    handleConfigChange('files', JSON.parse(e.target.value));
                  } catch {
                    // ignore
                  }
                }}
                rows={5}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg font-mono text-sm focus:ring-2 focus:ring-gray-400 focus:border-transparent"
                placeholder='{"/etc/passwd": "content"}'
              />
            </div>
          </div>
        </div>

        <div className="mt-6 flex justify_end">
          <button
            onClick={saveConfig}
            disabled={saving}
            className="flex items-center px-6 py-2 bg-gray-700 text-white rounded-lg hover:bg-gray-800 disabled:opacity-50"
          >
            <Save className="w-4 h-4 mr-2" />
            {saving ? 'Saving...' : 'Save Configuration'}
          </button>
        </div>
      </div>
    </div>
  );
};

// ---------- MAIN APP ----------

const App = () => {
  const [currentPage, setCurrentPage] = useState('dashboard');

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify_between items-center py-4">
            <div className="flex items-center space-x-3">
              <Shield className="w-8 h-8 text-gray-700" />
              <h1 className="text-2xl font-bold text-gray-800">
                IoT Honeypot Service
              </h1>
            </div>
            <nav className="flex space-x-1">
              <button
                onClick={() => setCurrentPage('dashboard')}
                className={`flex items-center px-4 py-2 rounded-lg transition-colors ${
                  currentPage === 'dashboard'
                    ? 'bg-gray-100 text-gray-900'
                    : 'text-gray-600 hover:bg-gray-50'
                }`}
              >
                <Activity className="w-4 h-4 mr-2" />
                Dashboard
              </button>
              <button
                onClick={() => setCurrentPage('settings')}
                className={`flex items-center px-4 py-2 rounded-lg transition-colors ${
                  currentPage === 'settings'
                    ? 'bg-gray-100 text-gray-900'
                    : 'text-gray-600 hover:bg-gray-50'
                }`}
              >
                <Settings className="w-4 h-4 mr-2" />
                Settings
              </button>
            </nav>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {currentPage === 'dashboard' ? <Dashboard /> : <SettingsPage />}
      </main>
    </div>
  );
};

export default App;
