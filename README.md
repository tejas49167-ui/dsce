# ML_logs_analyzer
#  AI Security Copilot – Suspicious Log Detection

##  Overview

AI Security Copilot is a web-based anomaly detection system that monitors user activity logs and detects suspicious behavior using machine learning.

The system simulates a real-world web application (e.g., calculator with login), stores user activity logs, and applies AI-based anomaly detection to identify abnormal usage patterns.

---

##  Problem Statement

Modern applications generate large volumes of logs.  
Manually monitoring these logs leads to:

-  Delayed threat detection  
-  High false positives  
-  Missed suspicious activities  

Our solution automates log analysis using ML-based anomaly detection.

---

## 🧠 Solution Approach

1. User interacts with the web application.
2. Backend stores activity logs in database.
3. Logs are converted into structured numeric features.
4. Isolation Forest detects anomalies.
5. System assigns a risk score.
6. Suspicious activities are flagged in the dashboard.

---

## 🏗 System Architecture
User → Web App → Backend → Database
↓
Feature Engineering
↓
Isolation Forest Model
↓
Alert System


