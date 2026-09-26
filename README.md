# PhishGuard — Hybrid Phishing URL Detection & Risk Analysis

PhishGuard is an application that analyzes URLs **as strings** without visiting, resolving, or executing them. It evaluates the structure and characteristics of a URL and classifies it as **LOW RISK, SUSPICIOUS, or HIGH RISK**, along with a 0–100 risk score and human-readable explanations.

The system combines a **Random Forest machine-learning classifier** with a **rule-based security engine** to provide both predictive analysis and interpretable security indicators. The analysis is exposed through a **FastAPI REST API** and presented through a dark, cyber-security themed **Streamlit threat detection console**.

### Key Features

* Hybrid ML + rule-based phishing URL detection
* 28 lexical and structural URL features
* Random Forest classification
* 0–100 hybrid risk scoring
* Explainable threat indicators and security reasons
* ML confidence and local feature drivers
* Suspicious keyword and domain analysis
* IP-based domain and subdomain detection
* URL shortener and punycode detection
* Suspicious TLD and unusual port detection
* Brand impersonation detection
* Domain and path entropy analysis
* Interactive threat detection dashboard
* Batch URL analysis through CSV files
* Scan history and result visualization
* JSON result export
* FastAPI REST API

### Detection Pipeline

```text
URL Input
    ↓
URL Validation & Parsing
    ↓
Feature Extraction
    ↓
┌─────────────────────┬─────────────────────┐
│   Random Forest     │    Rule Engine      │
│   ML Analysis       │    Security Rules   │
└──────────┬──────────┴──────────┬──────────┘
           ↓                     ↓
      ML Risk Score        Rule Risk Score
           └──────────┬──────────┘
                      ↓
              Hybrid Risk Score
                      ↓
        LOW / SUSPICIOUS / HIGH RISK
```

### Risk Analysis

PhishGuard combines machine-learning probability with rule-based security indicators to produce a final risk score.

The analysis can identify signals such as:

* Suspicious keywords such as `login`, `verify`, `account`, and `secure`
* IP addresses used as domains
* Excessive subdomains
* Suspicious top-level domains
* URL shorteners
* Punycode and non-ASCII domains
* Unusual ports
* Excessive special characters
* High domain or path entropy
* Brand names appearing in unrelated domains
* Suspicious URL structures

Each detected indicator is presented with a severity and plain-language explanation.

### Example

```text
HIGH RISK — 92/100

Reasons:
• Brand impersonation detected
• Multiple suspicious keywords
• Suspicious top-level domain
• Connection uses HTTP instead of HTTPS
```

### Technology Stack

**Backend:** Python, FastAPI, Pydantic
**Machine Learning:** Scikit-learn, Random Forest, NumPy, Pandas
**URL Analysis:** urllib.parse, tldextract
**Frontend:** Streamlit
**Visualization:** Plotly


### Project Structure

```text
app/
    FastAPI API, analysis engine, security rules and training

feature_engineering/
    URL feature extraction and detection configuration

dashboard/
    Streamlit interface, theme and visualizations

models/
    Trained Random Forest model and evaluation metrics

data/
    Dataset, generator and sample URLs

tests/
    Automated unit and API tests

docs/
    Architecture and interview documentation
```

### Security & Privacy

PhishGuard is designed around **safe URL-string analysis**.

Submitted URLs are never opened, crawled, resolved, or executed. The application validates untrusted input, escapes URLs before displaying them, and protects CSV exports against spreadsheet formula injection.

The current system performs lexical and structural analysis only. It does not currently use WHOIS data, DNS intelligence, TLS certificate information, reputation feeds, or webpage content.

### Dataset & Model

The bundled dataset and trained model are **synthetic/demo data** intended to demonstrate the complete ML pipeline.

The reported evaluation performance reflects patterns in the generated dataset and **should not be interpreted as real-world phishing detection accuracy**.

For production-level evaluation, the system would require large real-world phishing and legitimate URL datasets, domain-disjoint validation, temporal evaluation, and continuous monitoring for model drift.

### Future Improvements

* Real-world phishing intelligence datasets
* Domain reputation analysis
* WHOIS and domain-age features
* DNS and hosting intelligence
* TLS certificate analysis
* External threat-intelligence feeds
* Advanced model explainability
* Model drift monitoring
* Browser-extension integration
* Isolated webpage analysis and sandboxing


