# 🔐 Smart Contract Auditor

> AI-powered Solidity Smart Contract Security Auditor using **Google Gemini 3.8 Flash**.

Analyze Solidity smart contracts before deployment, detect common security vulnerabilities, calculate an overall security risk score, and generate detailed audit reports with AI-powered recommendations.

---

## 🚀 Features

- 🔍 AI-powered Solidity code analysis
- ⚠️ Detects common smart contract vulnerabilities
- 📊 Severity classification (Critical, High, Medium, Low)
- 📈 Overall security risk score
- 💡 Plain-English explanations
- ✅ Security recommendations
- 📄 Download audit reports as JSON
- 🖥️ Clean Streamlit interface
- 📚 Preloaded vulnerable smart contracts for testing

---

## 🛡️ Vulnerabilities Detected

- Reentrancy Attacks
- Integer Overflow / Underflow
- Access Control Issues
- Unsafe External Calls
- `tx.origin` Authentication
- Missing Input Validation
- Security Best Practice Violations

---

## 🏗️ Project Structure

```text
smart_contract_auditor/
│
├── app.py
├── auditor.py
├── requirements.txt
├── README.md
├── .env.template
├── .gitignore
│
├── contracts/
│   ├── __init__.py
│   └── examples.py
│
└── assets/
```

---

## ⚙️ Tech Stack

| Technology | Purpose |
|------------|---------|
| Python 3.10+ | Programming Language |
| Streamlit | Web Interface |
| Google Gemini 1.5 Flash | AI Security Analysis |
| google-generativeai | Gemini SDK |
| python-dotenv | Environment Variables |
| JSON | Audit Report Format |

---

## 🔄 Application Workflow

```text
              User
                │
                ▼
      Paste Solidity Contract
                │
                ▼
        Streamlit Application
                │
                ▼
      Google Gemini API Analysis
                │
                ▼
      Parse AI Security Findings
                │
                ▼
      Calculate Overall Risk Score
                │
                ▼
      Display Security Audit Report
                │
                ▼
      Download JSON Report
```

---

## 📦 Installation

### Clone the repository

```bash
git clone https://github.com/<your-username>/smart-contract-auditor.git

cd smart-contract-auditor
```

### Create Virtual Environment

```bash
python -m venv venv
```

### Activate Environment

**Windows**

```bash
venv\Scripts\activate
```

**Linux/macOS**

```bash
source venv/bin/activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Configure Environment Variables

Create a `.env` file.

```env
GEMINI_API_KEY=YOUR_API_KEY
```

### Run the Application

```bash
streamlit run app.py
```

Open

```
http://localhost:8501
```

---

## 🖥️ Usage

1. Launch the application.
2. Paste a Solidity smart contract.
3. Click **Run Security Audit**.
4. Review detected vulnerabilities.
5. Check severity levels and risk score.
6. Download the JSON audit report.

---

## 📊 Sample Audit Output

```json
{
  "contract_name": "VulnerableBank",
  "overall_risk_score": 85,
  "overall_risk_label": "CRITICAL",
  "findings": [
    {
      "vulnerability_name": "Reentrancy Attack",
      "severity": "Critical",
      "recommendation": "Apply Checks-Effects-Interactions pattern or use OpenZeppelin ReentrancyGuard."
    }
  ]
}
```

---

## 📚 Dependencies

```text
streamlit
google-generativeai
python-dotenv
```

---

## 🎯 Future Improvements

- GitHub Pull Request Integration
- VS Code Extension
- FastAPI Backend
- React Frontend
- PostgreSQL Audit History
- Inline Vulnerability Highlighting
- Multi-file Smart Contract Analysis
- Integration with Slither & Mythril
- Multi-chain Support
- AI-powered Secure Code Suggestions

---

