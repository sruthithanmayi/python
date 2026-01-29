Configuration management for CTI-IDS backend
"""

import os
from enum import Enum

class LogLevel(str, Enum):
DEBUG = "DEBUG"
INFO = "INFO"
WARNING = "WARNING"
ERROR = "ERROR"

class Config:
"""Application configuration"""

# API Configuration
API_TITLE = "CTI-IDS API"

32

API_VERSION = "1.0.0"
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", 8000))

# Logging
LOG_LEVEL = LogLevel(os.getenv("LOG_LEVEL", "INFO"))

# Model Configuration
MODEL_PATH = os.getenv("MODEL_PATH", "./models/")
BERT_MODEL = "bert-base-uncased"
LSTM_HIDDEN_UNITS = 64
CNN_INPUT_SHAPE = (224, 224, 3)

# Cache Configuration
CACHE_SIZE = int(os.getenv("CACHE_SIZE", 1000))
CACHE_TTL = 3600 # 1 hour

# Alert Thresholds
IDS_ALERT_THRESHOLD = 0.75
CRITICAL_THREAT_THRESHOLD = 0.75
HIGH_THREAT_THRESHOLD = 0.6
MEDIUM_THREAT_THRESHOLD = 0.4

# API Endpoints
VIRUSTOTAL_API_TIMEOUT = 10
URLHAUS_API_TIMEOUT = 10
SHODAN_API_TIMEOUT = 10

33

# Database (optional)
DATABASE_URL = os.getenv(
"DATABASE_URL",
"postgresql://threat_admin:secure_password@localhost:5432/cti_ids"
)

@classmethod
def get_config(cls):
"""Get current configuration"""
return {
"api_title": cls.API_TITLE,
"api_version": cls.API_VERSION,
"log_level": cls.LOG_LEVEL.value,
"model_path": cls.MODEL_PATH,
"cache_size": cls.CACHE_SIZE,
}
config = Config()
Cti_Pipeline.py:
"""
Enhanced Cyber Threat Intelligence (CTI) Pipeline
Real-time processing with actual API integrations
"""

import logging
from typing import Dict, List, Any
from datetime import datetime
import os
from dotenv import load_dotenv

34

from integrations.threat_intel_apis import (
VirusTotalAPI, AbuseIPDBAPI, OTXAPIIntegration, ShodanAPI, ThreatIntelAggregator
)

load_dotenv()

logger = logging.getLogger(__name__)

class CTIPipeline:
"""Enhanced CTI data ingestion with real API sources"""

def __init__(self):
self.vt = VirusTotalAPI()
self.abuseipdb = AbuseIPDBAPI()
self.otx = OTXAPIIntegration()
self.shodan = ShodanAPI()
self.aggregator = ThreatIntelAggregator()

self.sources = {
'virustotal': 'VirusTotal API',
'abuseipdb': 'AbuseIPDB API',
'otx': 'OTX API',
'shodan': 'Shodan API',
}
self.cache = {}
logger.info("Initialized Enhanced CTI Pipeline with real API integrations")

35
def fetch_threat_data(self, indicator: str) -> Dict[str, Any]:
"""Fetch threat intelligence from real APIs for an indicator"""

logger.info(f"Fetching real CTI data for indicator: {indicator}")

# Check cache first
if indicator in self.cache:
logger.info(f"Using cached CTI data for: {indicator}")
return self.cache[indicator]

threat_data = self.aggregator.analyze_indicator(indicator)

risk_level = "Unknown"
if threat_data.get('aggregated_risk_score', 0) > 0.8:
risk_level = "Critical"
elif threat_data.get('aggregated_risk_score', 0) > 0.6:
risk_level = "High"
elif threat_data.get('aggregated_risk_score', 0) > 0.4:
risk_level = "Medium"
else:
risk_level = "Low"

threat_data['risk_level'] = risk_level
threat_data['last_updated'] = datetime.now().isoformat()

# Cache the result
self.cache[indicator] = threat_data

36

return threat_data

def process_batch(self, indicators: List[str]) -> List[Dict[str, Any]]:
"""Process multiple indicators in batch"""
logger.info(f"Processing batch of {len(indicators)} indicators with real APIs")

results = []
for indicator in indicators:
result = self.fetch_threat_data(indicator)
results.append(result)

return results

def get_cached_data(self, indicator: str) -> Dict[str, Any]:
"""Retrieve cached threat data if available"""
return self.cache.get(indicator, None)
IDS_Pipeline.py:
"""
Intrusion Detection System (IDS) Pipeline
Processes network traffic and behavioral data
"""

import logging
import numpy as np
from typing import Dict, List, Any
from datetime import datetime

logger = logging.getLogger(__name__)

37

class IDSPipeline:
"""IDS data processing and anomaly detection pipeline"""

def __init__(self):
self.preprocessor = IDSDataPreprocessor()
self.alert_threshold = 0.75
logger.info("Initialized IDS Pipeline")

def process_network_traffic(self, packets: List[Dict]) -> Dict[str, Any]:
"""Process and analyze network traffic packets"""

logger.info(f"Processing {len(packets)} network packets")

# Convert packets to feature vectors
features = self.preprocessor.extract_features(packets)

# Simulated anomaly detection
anomaly_scores = np.random.uniform(0, 1, len(packets))
alerts = []

for idx, (packet, score) in enumerate(zip(packets, anomaly_scores)):
if score > self.alert_threshold:
alerts.append({
'packet_id': idx,
'src_ip': packet.get('src_ip', 'unknown'),
'dst_ip': packet.get('dst_ip', 'unknown'),
'port': packet.get('port', 'unknown'),

38

'anomaly_score': float(score),
'alert_type': self._classify_alert(packet, score),
})

return {
'total_packets': len(packets),
'anomalies_detected': len(alerts),
'anomaly_rate': float(np.mean(anomaly_scores)),
'alerts': alerts,
'timestamp': datetime.now().isoformat(),
}

def _classify_alert(self, packet: Dict, score: float) -> str:
"""Classify the type of security alert"""
if score > 0.9:
return 'Potential DDoS Attack'
elif score > 0.8:
return 'Port Scanning Detected'
elif score > 0.75:
return 'Unusual Traffic Pattern'
return 'Anomaly Detected'

def process_user_behavior(self, events: List[Dict]) -> Dict[str, Any]:
"""Analyze user behavior for insider threats"""

logger.info(f"Analyzing {len(events)} user behavior events")

# Simulated behavioral analysis

39

suspicious_events = []
for event in events:
if event.get('action') in ['file_delete', 'data_export', 'privilege_change']:
suspicious_events.append({
'user': event.get('user'),
'action': event.get('action'),
'timestamp': event.get('timestamp'),
'risk_score': np.random.uniform(0.5, 1.0),
})

return {
'total_events': len(events),
'suspicious_events': len(suspicious_events),
'events': suspicious_events,
}

class IDSDataPreprocessor:
"""Preprocesses raw network data for IDS analysis"""

def extract_features(self, packets: List[Dict]) -> np.ndarray:
"""Extract ML features from network packets"""
features = []

for packet in packets:
packet_features = [
len(packet.get('payload', '')),
hash(packet.get('protocol', '')) % 256,
hash(packet.get('src_ip', '')) % 256,

40
hash(packet.get('dst_ip', '')) % 256,
]
features.append(packet_features)

return np.array(features) if features else np.array([])
def normalize_features(self, features: np.ndarray) -> np.ndarray:
"""Normalize feature vectors to 0-1 range"""
if features.size == 0:
return features

min_vals = np.min(features, axis=0)
max_vals = np.max(features, axis=0)

return (features - min_vals) / (max_vals - min_vals + 1e-6)
Page.tsx:
"use client"

import { useState } from "react"
import { ThreatAnalyzerForm } from "@/components/threat-analyzer-form"
import { ThreatDashboard } from "@/components/threat-dashboard"
import { ModelMetrics } from "@/components/model-metrics"
import { APILogsViewer } from "@/components/api-logs-viewer"
import { LoadingAnimation } from "@/components/loading-animation"
import { Header } from "@/components/header"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"

export default function Home() {
const [threatResult, setThreatResult] = useState(null)

41
const [loading, setLoading] = useState(false)
const [metrics, setMetrics] = useState(null)
const [activeTab, setActiveTab] = useState("analysis")

const handleAnalyze = async (data: any) => {
setLoading(true)
try {
setThreatResult(data)
setActiveTab("results")

// Fetch real metrics from backend
try {
const metricsResponse = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/metrics`)
const metricsData = await metricsResponse.json()
setMetrics(metricsData)
} catch (err) {
console.error("Failed to fetch metrics:", err)
}
} finally {
setLoading(false)
}
}

return (
<main className="min-h-screen bg-background">
<Header />
<div className="container mx-auto px-4 py-8">
<Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">

42
<TabsList className="grid w-full grid-cols-3 bg-muted">
<TabsTrigger value="analysis">Analysis</TabsTrigger>

<TabsTrigger value="results">Results {loading && <span className="ml-2 animate-
spin">⟳</span>}</TabsTrigger>

<TabsTrigger value="logs">Logs & Monitoring</TabsTrigger>
</TabsList>

<TabsContent value="analysis" className="space-y-6">
{loading && (
<div className="flex justify-center items-center py-12">
<LoadingAnimation />
</div>
)}
{!loading && (
<div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
<div className="lg:col-span-1">
<ThreatAnalyzerForm onAnalyze={handleAnalyze} loading={loading} />
</div>
<div className="lg:col-span-2">{threatResult && <ThreatDashboard result={threatResult} />}</div>
</div>
)}
</TabsContent>

<TabsContent value="results" className="space-y-6">
{loading ? (
<div className="flex justify-center items-center py-16">
<LoadingAnimation />
</div>
) : threatResult ? (

43

<div className="space-y-6">
<ThreatDashboard result={threatResult} />
{metrics && <ModelMetrics metrics={metrics} />}
</div>
) : (
<div className="text-center text-muted-foreground py-12">
No analysis results yet. Submit a threat analysis to see results.
</div>
)}
</TabsContent>

<TabsContent value="logs" className="space-y-6">
<APILogsViewer />
</TabsContent>
</Tabs>
</div>
</main>
)
}
Logger.ts:
// Comprehensive logging system for frontend request/response tracking and debugging
type LogLevel = "debug" | "info" | "warn" | "error"

interface LogEntry {
timestamp: string
level: LogLevel
component: string
message: string

44

data?: any
duration?: number
}

class Logger {
private logs: LogEntry[] = []
private maxLogs = 1000

private getLogLevel(): LogLevel {
const level = process.env.NEXT_PUBLIC_LOG_LEVEL || "info"
return level as LogLevel
}

private shouldLog(level: LogLevel): boolean {
const levels: Record<LogLevel, number> = {
debug: 0,
info: 1,
warn: 2,
error: 3,
}
return levels[level] >= levels[this.getLogLevel()]
}

private formatLog(entry: LogEntry): string {
const { timestamp, level, component, message, duration } = entry
const durationStr = duration ? ` [${duration.toFixed(2)}ms]` : ""
return `[${timestamp}] [${level.toUpperCase()}] [${component}]${durationStr} ${message}`
}

45

log(level: LogLevel, component: string, message: string, data?: any) {
if (!this.shouldLog(level)) return

const entry: LogEntry = {
timestamp: new Date().toISOString(),
level,
component,
message,
data,
}

this.logs.push(entry)
if (this.logs.length > this.maxLogs) {
this.logs.shift()
}

if (process.env.NEXT_PUBLIC_ENABLE_CONSOLE_LOGS !== "false") {
const formatted = this.formatLog(entry)
const logFn = level === "error" ? console.error : level === "warn" ? console.warn : console.log
logFn(formatted, data || "")
}
}

debug(component: string, message: string, data?: any) {
this.log("debug", component, message, data)
}

46
info(component: string, message: string, data?: any) {
this.log("info", component, message, data)
}

warn(component: string, message: string, data?: any) {
this.log("warn", component, message, data)
}

error(component: string, message: string, data?: any) {
this.log("error", component, message, data)
}

getLogs(limit = 100): LogEntry[] {
return this.logs.slice(-limit)
}

clearLogs() {
this.logs = []
}

exportLogs(): string {
return JSON.stringify(this.logs, null, 2)
}
}
export const logger = new Logger()
