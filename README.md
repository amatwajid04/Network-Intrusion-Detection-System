#  Network Intrusion Detection System

A web-based **Machine Learning** application that analyzes network traffic data and predicts whether connections are **Normal** or one of four attack types: **DoS**, **Probe**, **R2L**, or **U2R**.

Built as a university semester project using **Flask**, **Scikit-learn**, and **Chart.js**.

---

##  Project Overview

| Feature | Details |
|---------|---------|
| **ML Model** | Random Forest Classifier |
| **Dataset** | Synthetic NSL-KDD (auto-generated) |
| **Backend** | Python, Flask |
| **Frontend** | HTML, CSS, JavaScript, Chart.js |
| **Attack Types** | DoS, Probe, R2L, U2R |
| **Output** | Dashboard + PDF Report |

### What This System Does

1. **Trains** a machine learning model on synthetic network traffic data
2. **Accepts** CSV file uploads through a web interface
3. **Predicts** whether each traffic record is normal or an attack
4. **Visualizes** results with interactive charts and a severity meter
5. **Generates** downloadable PDF reports

---

##  Installation Steps

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Step 1: Clone or Download

```bash
cd network_intrusion_detection
```

### Step 2: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 3: Train the Model

```bash
python train_model.py
```

This will:
- Generate synthetic training data (5000 records)
- Train and compare 3 ML models
- Save the Random Forest model to `model/intrusion_model.pkl`
- Create a sample CSV file in `dataset/sample_data.csv`

### Step 4: Run the Web App

```bash
python app.py
```

### Step 5: Open in Browser

Navigate to: **http://127.0.0.1:5000**

---

##  Project Structure

```
network_intrusion_detection/
│
├── app.py                  # Flask web application (main file)
├── train_model.py          # ML model training script
├── requirements.txt        # Python dependencies
│
├── model/
│   ├── intrusion_model.pkl     # Trained Random Forest model
│   └── model_comparison.json   # Accuracy comparison data
│
├── dataset/
│   └── sample_data.csv         # Sample CSV for testing
│
├── templates/
│   ├── index.html              # Home page (upload form)
│   ├── dashboard.html          # Results dashboard
│   └── report.html             # Printable report page
│
├── static/
│   ├── css/
│   │   └── style.css           # Dark cybersecurity theme
│   ├── js/
│   │   └── dashboard.js        # Chart.js charts
│   └── images/                 # (placeholder for images)
│
└── README.md                   # This file
```

---

##  Dataset Information

### NSL-KDD Dataset (Synthetic Version)

The project uses **synthetically generated data** that mimics the structure and patterns of the real [NSL-KDD dataset](https://www.unb.ca/cic/datasets/nsl.html). This approach:

- Keeps the project **self-contained** (no external downloads needed)
- Makes it **reproducible** across different environments
- Allows students to **modify** data generation parameters

### Features Used

| Feature | Description |
|---------|-------------|
| `duration` | Connection length in seconds |
| `protocol_type` | Protocol (tcp, udp, icmp) |
| `service` | Network service (http, ftp, ssh, etc.) |
| `flag` | Connection status (SF, S0, REJ, etc.) |
| `src_bytes` | Bytes from source to destination |
| `dst_bytes` | Bytes from destination to source |
| `count` | Connections to same host in 2 sec |
| `srv_count` | Connections to same service in 2 sec |
| `serror_rate` | % SYN error connections |
| `same_srv_rate` | % same-service connections |
| `dst_host_count` | Connections to destination host |
| `dst_host_srv_count` | Same destination & service count |
| `dst_host_same_srv_rate` | % same-service at destination |
| `dst_host_serror_rate` | % SYN errors at destination |

### Attack Types

| Type | Description | Risk Level |
|------|-------------|------------|
| **Normal** | Regular network traffic | 🟢 Low |
| **DoS** | Denial of Service (flood attacks) | 🔴 High |
| **Probe** | Network scanning/surveillance | 🟡 Medium |
| **R2L** | Remote-to-Local unauthorized access | 🔴 High |
| **U2R** | User-to-Root privilege escalation | 🔴 High |

---

##  Machine Learning Details

### Models Compared

| Model | Purpose |
|-------|---------|
| **Random Forest** | Primary model (100 trees, max depth 15) — **Deployed** |
| **Decision Tree** | Comparison model (simpler alternative) |
| **Logistic Regression** | Comparison model (linear baseline) |

### Evaluation Metrics

- **Accuracy** — Overall correct predictions
- **Precision** — Of predicted attacks, how many were real attacks?
- **Recall** — Of real attacks, how many were detected?
- **F1 Score** — Harmonic mean of precision and recall

---

##  Screenshots

> Add screenshots here after running the application.

1. **Home Page** — Upload interface with drag-and-drop support
2. **Dashboard** — Summary cards, severity meter, and interactive charts
3. **Report** — Printable analysis report with PDF download

---

##  Future Improvements

- [ ] Use the real NSL-KDD dataset for training
- [ ] Add more ML models (SVM, Neural Network, XGBoost)
- [ ] Real-time network traffic monitoring
- [ ] User authentication system
- [ ] Database storage for analysis history
- [ ] Feature importance visualization
- [ ] Confusion matrix display
- [ ] Model retraining through the web interface
- [ ] API endpoint for external integrations

---

##  Technologies Used

| Technology | Purpose |
|-----------|---------|
| Python 3 | Backend programming language |
| Flask | Web framework |
| Scikit-learn | Machine learning library |
| Pandas | Data manipulation |
| NumPy | Numerical computing |
| Chart.js | Interactive chart visualization |
| fpdf2 | PDF report generation |
| HTML/CSS/JS | Frontend interface |

---

##  Author

University Machine Learning Semester Project

---

##  License

This project is for educational purposes only.
