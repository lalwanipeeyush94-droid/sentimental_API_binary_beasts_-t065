# 🛡️ SentinelAPI

### AI-Powered API Security Scanning & Vulnerability Analysis Platform

SentinelAPI is an AI-assisted API security platform designed to automatically discover, analyze, and identify security vulnerabilities in APIs.

The platform combines automated API scanning, machine-learning-based analysis, security testing techniques, evidence collection, and structured reporting into a unified workflow.

---

## 🚀 Project Overview

Modern applications heavily depend on APIs for communication between frontend applications, backend services, databases, and third-party systems.

However, APIs can contain vulnerabilities such as:

- Broken Object Level Authorization (BOLA)
- Improper authorization
- Authentication weaknesses
- Input validation issues
- Suspicious API behavior
- Misconfigured endpoints
- Potentially vulnerable API parameters

Manual API security testing can be time-consuming and difficult to scale.

**SentinelAPI** aims to automate significant parts of this process by combining traditional security scanning with AI/ML-assisted analysis.

---

## 🎯 Objectives

The primary objectives of SentinelAPI are:

1. Automatically discover API endpoints.
2. Analyze API behavior and responses.
3. Detect potential security vulnerabilities.
4. Identify possible BOLA/authorization issues.
5. Use ML-assisted analysis for vulnerability prediction.
6. Collect evidence for detected findings.
7. Generate structured security reports.
8. Provide a simple web-based interface for security analysis.

---

## 🧩 Key Features

### 🔍 Automated API Discovery

SentinelAPI can scan and discover API endpoints that need to be analyzed.

The scanner can process API information and identify endpoints, parameters, and responses for further security testing.

---

### 🛡️ BOLA Detection

One of the important security checks implemented in SentinelAPI is **Broken Object Level Authorization (BOLA)** analysis.

The system analyzes object-level API access patterns to identify situations where users may potentially access resources that they are not authorized to access.

> BOLA findings should be treated as potential vulnerabilities and manually validated before being considered confirmed security issues.

---

### 🤖 AI / ML-Assisted Analysis

SentinelAPI contains an ML pipeline that can assist with vulnerability analysis.

The ML workflow includes components such as:

- Dataset preparation
- Feature processing
- Model training
- Prediction
- Vulnerability classification

Relevant project components include:

```text
backend/ml/
├── predictor.py
├── prepare_kaggle.py
└── train.py
