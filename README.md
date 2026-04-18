<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Flask-2.3-000000?style=for-the-badge&logo=flask&logoColor=white" alt="Flask">
  <img src="https://img.shields.io/badge/scikit--learn-1.3-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white" alt="scikit-learn">
  <img src="https://img.shields.io/badge/Bootstrap-5.3-7952B3?style=for-the-badge&logo=bootstrap&logoColor=white" alt="Bootstrap">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
</p>

<h1 align="center">🔒 PhishGuard</h1>
<h3 align="center">AI-Powered Phishing URL Detection System</h3>
<p align="center">
  A hybrid Machine Learning + Rule-based engine that detects phishing URLs in real-time with ~95% accuracy.
  <br/>
  Built with Flask, scikit-learn, and a modern dark-themed UI featuring live scanner animations.
</p>

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🧠 **Hybrid Detection** | Combines Random Forest ML (70%) + Rule-based scoring (30%) for robust predictions |
| 🔍 **30 UCI Features** | Extracts URL length, IP presence, HTTPS status, subdomains, suspicious TLDs & more |
| ⚡ **Real-time Scanning** | Analyze any URL in under 2 seconds with detailed threat breakdown |
| 🛡️ **Smart Overrides** | Auto-classifies known-safe domains (50+) and obvious phishing patterns |
| 📊 **Rich Results** | Domain info, SSL certificate, hosting provider, geolocation, threat intelligence |
| 🎨 **Modern UI** | Dark glassmorphism design with animated radar scanner and responsive layout |
| 🔌 **REST API** | JSON endpoint (`POST /predict`) for easy integration with other tools |

## 🖼️ Screenshots

<details>
<summary><b>Home Page — Animated Scanner Hero</b></summary>
<br/>
<p>Professional landing page with a rotating radar scanner animation, trust statistics, and feature highlights.</p>
</details>

<details>
<summary><b>URL Checker — Live Threat Analysis</b></summary>
<br/>
<p>Enter any URL to get instant results with confidence score, threat breakdown, SSL info, domain analysis, and human-readable explanations.</p>
</details>

## 🚀 Quick Start

### Prerequisites

- Python 3.10 or higher
- pip (Python package manager)

### Installation

```bash
# Clone the repository
git clone https://github.com/raajks/PhishGuard.git
cd PhishGuard

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate        # Linux/macOS
venv\Scripts\activate           # Windows

# Install dependencies
pip install -r requirements.txt
```

### Run the App

```bash
python app.py
```

Open **http://localhost:5000** in your browser.

### Train with Real Dataset (Optional)

The app ships with a pre-trained `model.pkl`. To retrain on the UCI Phishing Websites dataset (11,055 samples):

```bash
python train_model.py
```

This downloads the dataset from the [UCI ML Repository](https://archive.ics.uci.edu/ml/datasets/Phishing+Websites) and trains a new Random Forest model.

## 🏗️ Architecture

```
PhishGuard/
├── app.py               # Flask server, routes, prediction pipeline
├── utils.py             # Feature extraction, rule engine, hybrid scoring
├── train_model.py       # Dataset download & model training script
├── model.pkl            # Pre-trained Random Forest model (~53KB)
├── requirements.txt     # Python dependencies
├── .gitignore
│
├── templates/
│   ├── home.html        # Landing page with scanner animation
│   ├── checker.html     # URL analysis interface
│   └── index.html       # Alternate index
│
└── static/
    ├── css/
    │   ├── style.css        # Global styles + navbar overrides
    │   ├── scanner.css      # Scanner animation styles
    │   └── hacker-style.css # Alternative theme
    └── js/
        └── script.js        # Frontend API calls & UI logic
```

## ⚙️ How It Works

```
URL Input → Validation → Feature Extraction (30 features)
                              ↓
              ┌───────────────┴───────────────┐
              │                               │
       ML Prediction (70%)          Rule-based Score (30%)
    Random Forest Classifier      Keyword, TLD, IP, HTTPS checks
              │                               │
              └───────────────┬───────────────┘
                              ↓
                     Hybrid Score (0-100)
                              ↓
                     Override Rules Applied
                              ↓
               Safe | Suspicious | Phishing
```

### Detection Pipeline

1. **URL Validation** — Rejects garbage input, auto-adds protocol
2. **Feature Extraction** — 30 UCI-standard features (IP detection, URL length, HTTPS, shortener detection, subdomain count, etc.)
3. **ML Prediction** — Random Forest with 100 trees, max_depth=15 → phishing probability
4. **Rule-based Scoring** — Pattern matching against suspicious keywords, TLDs, IP addresses → risk score (0–100)
5. **Hybrid Fusion** — `(ML × 0.7) + (Rules × 0.3)` → final confidence
6. **Smart Overrides** — Known-safe domains forced Safe; IP-only URLs forced Suspicious; login + no HTTPS forced Phishing

## 🔌 API Reference

### `POST /predict`

Analyze a URL for phishing threats.

**Request:**
```json
{
  "url": "https://example.com"
}
```

**Response:**
```json
{
  "success": true,
  "url": "https://example.com",
  "prediction": "Safe",
  "confidence": 92.5,
  "score_breakdown": {
    "ml_score": 8.2,
    "rule_score": 5.0,
    "hybrid_score": 7.24
  },
  "domain_info": { "domain": "example.com", "tld": "com", "protocol": "https" },
  "certificate": { "valid": true, "issued_by": "Let's Encrypt" },
  "hosting": { "name": "Cloudflare", "type": "CDN" },
  "location": { "country": "US" },
  "threat_intelligence": { "malware_detected": false },
  "explanation": { "summary": "This URL appears safe..." }
}
```

### `GET /health`

Health check endpoint.

```json
{ "status": "healthy", "model_loaded": true }
```

## 🧪 Example Tests

```bash
# Safe URL
curl -X POST http://localhost:5000/predict \
  -H "Content-Type: application/json" \
  -d '{"url": "https://google.com"}'

# Suspicious URL
curl -X POST http://localhost:5000/predict \
  -H "Content-Type: application/json" \
  -d '{"url": "http://192.168.1.1"}'

# Phishing URL
curl -X POST http://localhost:5000/predict \
  -H "Content-Type: application/json" \
  -d '{"url": "http://free-login-secure.xyz"}'
```

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | Python, Flask 2.3 |
| **ML Model** | scikit-learn RandomForestClassifier (100 trees) |
| **Dataset** | UCI Phishing Websites (11,055 samples, 30 features) |
| **Frontend** | HTML5, CSS3, JavaScript, Bootstrap 5.3 |
| **Fonts** | Inter, JetBrains Mono |
| **Icons** | Font Awesome 6.5 |
| **Design** | Dark glassmorphism, animated radar scanner |

## 📈 Model Performance

| Metric | Score |
|--------|-------|
| Accuracy | ~95% |
| Precision | ~94% |
| Recall | ~95% |
| F1-Score | ~94% |

*Trained on UCI Phishing Websites dataset with 80/20 stratified split.*

## 📝 Research Paper

This project is part of an academic research:

> **A Survey on Phishing Detection Techniques: From Traditional Methods to Machine and Deep Learning Approaches**
>
> *Rajkumar Sharma, Arjoo Jain, Swati Nagar — Sunder Deep Engineering College (SDEC)*

Phishing attacks have become a major cybersecurity threat. This paper presents a comprehensive survey covering the progression from traditional approaches to advanced ML and deep learning-based methods, categorized into four groups: list-based, heuristic/similarity-based, machine learning-based, and deep learning-based models.

| Item | Details |
|------|---------|
| **Authors** | Rajkumar Sharma, Arjoo Jain, Swati Nagar |
| **Institution** | Sunder Deep Engineering College (SDEC) |
| **Keywords** | Phishing Detection, Cybersecurity, ML, Deep Learning, URL Analysis |
| **Dataset** | UCI Phishing Websites (11,055 samples, 30 features) |
| **Key Contribution** | Comprehensive survey + Hybrid ML + Rule-based engine (PhishGuard) |
| **Paper Outline** | [`research/paper_outline.txt`](research/paper_outline.txt) |
| **Status** | 🔄 In Progress |

See the [`research/`](research/) folder for the full paper outline, references, and PDF (when published).

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [UCI Machine Learning Repository](https://archive.ics.uci.edu/ml/datasets/Phishing+Websites) — Phishing Websites dataset
- [scikit-learn](https://scikit-learn.org/) — Machine Learning library
- [Flask](https://flask.palletsprojects.com/) — Web framework
- [Bootstrap](https://getbootstrap.com/) — CSS framework
- [Font Awesome](https://fontawesome.com/) — Icons

---

<p align="center">
  Made with ❤️ for a safer internet
</p>
