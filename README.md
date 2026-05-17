# SecureWatch AI: Gemini-Powered SIEM & SOC Platform

![SecureWatch AI Banner](https://img.shields.io/badge/Security-AI_Powered-blueviolet?style=for-the-badge&logo=google-gemini)
![Django](https://img.shields.io/badge/django-%23092E20.svg?style=for-the-badge&logo=django&logoColor=white)
![React](https://img.shields.io/badge/react-%2320232b.svg?style=for-the-badge&logo=react&logoColor=%2361DAFB)
![TailwindCSS](https://img.shields.io/badge/tailwindcss-%2338B2AC.svg?style=for-the-badge&logo=tailwind-css&logoColor=white)

**SecureWatch AI** is a professional-grade Security Information and Event Management (SIEM) platform that integrates **Google Gemini 2.5 Flash** to provide real-time, autonomous threat hunting and log forensics. Designed for modern SOC (Security Operations Center) workflows, it processes Windows Sysmon logs directly from Winlogbeat to identify multi-stage attacks.

## 🚀 Key Features

*   **🧠 Gemini AI Analyst**: Real-time analysis of every ingested log. Gemini identifies behaviors like lateral movement, credential compromise, and defense evasion.
*   **🛡️ Instant Forensics**: A specialized "Investigator" tool allows analysts to paste any raw log for immediate deep-packet inspection by AI.
*   **📈 Forensic Dashboard**: High-impact visualization of fleet telemetry, threat velocity, and risk distribution.
*   **🔐 Identity & Access (RBAC)**: Comprehensive operator management with Role-Based Access Control (Admin, Analyst, Viewer).
*   **⚡ Direct Ingestion**: Optimized for high-speed log ingestion from Winlogbeat without the complexity of Kafka.
*   **📱 Session Intelligence**: Advanced tracking of operator login metadata, device fingerprints, and security posture.

## 🛠️ Technology Stack

*   **Backend**: Django, Django REST Framework, SimpleJWT (Auth)
*   **Frontend**: React (Vite), Tailwind CSS, Lucide Icons
*   **AI Engine**: Google Gemini 2.5 Flash API
*   **Telemetry**: Windows Sysmon + Winlogbeat Ingestion

## 📋 Installation & Setup

### 1. Backend Setup
```bash
# Clone the repository
git clone https://github.com/yourusername/securewatch-ai.git
cd securewatch-ai/backend

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env and add your GEMINI_API_KEY

# Run migrations and setup test users
python manage.py migrate
python create_test_users.py

# Start server
python manage.py runserver
```

### 2. Frontend Setup
```bash
cd ../frontend
npm install
npm run dev
```

## ⚙️ Ingestion Configuration (Winlogbeat)
Point your Winlogbeat `http` output to the following endpoint:
`http://localhost:8000/api/v1/logs/sysmon/`

## 👤 Test Credentials
*   **Admin**: `admin` / `admin123`
*   **Analyst**: `analyst` / `analyst123`


