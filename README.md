# 🛡️ Synapse – Pix Fraud Prevention Platform

Synapse is an intelligent fraud prevention platform designed for the Brazilian Pix ecosystem. The project leverages Machine Learning, behavioral analytics, transaction monitoring, and risk scoring engines to identify suspicious activities in real time and support fraud prevention decision-making.

The platform transforms transactional behavior, account signals, device intelligence, and network indicators into explainable risk scores that help financial institutions, payment processors, fintechs, and fraud analysts detect and prevent fraud before losses occur.

---

## 🎯 Project Objectives

- Detect suspicious Pix transactions in real time
- Identify mule accounts and scammer networks
- Monitor transactional behavior and anomalies
- Generate dynamic fraud scores
- Support analyst investigations
- Improve risk-based decision making
- Reduce fraud exposure and operational losses
- Provide visibility into transaction patterns and account behavior

---

## 🚀 Key Features

### Authentication and Access Control

- Secure user authentication
- Role-based access
- Analyst and administrator profiles
- Audit-ready workflows

### Synapse Dashboard

Executive dashboard with:

- Total TPV (Total Payment Volume)
- Total monitored accounts
- Suspicious account indicators
- Fraud alert monitoring
- Risk score visualization
- Behavioral metrics

### Pix Key Investigation

Search and investigate:

- CPF Keys
- CNPJ Keys
- Email Keys
- Phone Keys
- Random Pix Keys

Analysis includes:

- Risk score
- Risk classification
- Transaction volume
- Historical activity
- Behavioral indicators

### Account Validation

Account-level investigation including:

- Account profile
- Transaction history
- Device information
- Linked Pix keys
- Behavior analysis
- Fraud indicators

### Fraud Scoring Engine

The scoring engine evaluates multiple variables such as:

- Transaction velocity
- Device changes
- Geolocation anomalies
- Behavioral patterns
- Known suspicious destinations
- Dictionary and fraud markers
- Historical fraud indicators

### Behavior Analytics

Behavior monitoring features:

- Geographical visualization
- Transaction clusters
- Movement patterns
- Device intelligence
- Regional risk concentration
- Fraud hotspot detection

### Alert Center

Real-time alert management:

- High-risk transactions
- Suspicious accounts
- Fraud pattern detection
- Risk escalation workflows

---

## 🧠 Machine Learning Approach

Synapse uses machine learning and behavioral analysis techniques to transform transactional data into risk intelligence.

The platform can incorporate:

- Supervised learning models
- Unsupervised anomaly detection
- Feature engineering pipelines
- Behavioral scoring models
- Fraud network analysis
- Risk classification algorithms

Example fraud categories:

| Category | Description |
|-----------|------------|
| Account OK | Low-risk account |
| Suspicious | Requires monitoring |
| Mule Account | Potential intermediary account |
| Application Fraud | Fraud during onboarding |
| Scammer Account | High-risk confirmed pattern |

---

## 🏦 Pix Ecosystem Focus

Built specifically for the Brazilian Instant Payments ecosystem:

- Pix transaction monitoring
- Fraud signal enrichment
- Behavioral transaction analysis
- Anti-money mule detection
- Scam prevention support
- Financial crime monitoring

---

## 📊 Analytics and Monitoring

The platform provides:

- TPV analysis
- Volume monitoring
- Fraud trend analysis
- Category distribution
- Risk concentration analysis
- Alert history
- Geospatial intelligence

---

## 🛠 Technology Stack

- Python
- Streamlit
- Pandas
- NumPy
- Altair
- Machine Learning Models
- Risk Scoring Engine

Potential future integrations:

- PostgreSQL
- Snowflake
- Databricks
- FastAPI
- Azure
- AWS
- Kafka
- Redis

---

## 📁 Project Structure

```text
Synapse/
│
├── app.py
├── requirements.txt
├── README.md
│
├── pages/
│   ├── dashboard.py
│   ├── pix_investigation.py
│   ├── accounts.py
│   ├── scoring.py
│   ├── behavior.py
│   └── alerts.py
│
├── assets/
│
└── data/
