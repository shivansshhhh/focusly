# 🌟 Focusly – Smart Task Manager

> A modern task management web app to help you organize life, boost productivity, and stay focused.  
> Built with **Flask**, **Firebase**, **Google OAuth**, and **TailwindCSS**.

![Dashboard Screenshot](backend/static/images/og.png)

---

## ✨ Features

- 🔑 **Authentication**
  - Sign in with **Google OAuth**
  - Sign in with **Phone Authentication** via Firebase
  - Secure session management with Flask
- 📊 **User Data Management**
  - Store user profiles in Firebase Firestore
  - Track last login and user activity
- ⏳ **Pomodoro Timer**
  - Pomodoro, Short Break, and Long Break modes
  - Responsive timer with reset functionality
- 🌍 **Smart Geo Detection**
  - Auto-detect user country for phone login
- 🎨 **Beautiful UI**
  - Fully responsive landing page
  - Smooth animations & TailwindCSS design
- 🔒 **Security Features**
  - No-cache headers for sensitive pages
  - Firebase custom tokens for client authentication

---

## 🛠 Tech Stack

- **Backend:** [Flask](https://flask.palletsprojects.com/) (Python)
- **Frontend:** [TailwindCSS](https://tailwindcss.com/) + Jinja Templates
- **Authentication:** [Firebase Auth](https://firebase.google.com/docs/auth)
- **Deployment:** Compatible with Heroku / Render / AWS / GCP
- **Environment Management:** Python-dotenv
- **Database:** [Firebase Firestore](https://firebase.google.com/docs/firestore)
- **Database-Er-diagram:**
- ![ER Diagram](database-er-diagram.png)
- **Data Dictionary**👇

  Collection: users

    | Field        | Type     | Description                       |
    |--------------|----------|-----------------------------------|
    | uid          | string   | Firebase UID (Primary Key)        |
    | email        | string   | User's email                      |
    | phone        | string   | User's phone number               |
    | created_at   | datetime | Account creation timestamp        |


  Subcollection: tasks

    | Field         | Type     | Description                                 |
    |---------------|----------|---------------------------------------------|
    | task_id       | string   | Task Document ID                            |
    | title         | string   | Title of the task                           |
    | description   | string   | Detailed description                        |
    | due_date      | datetime | Task deadline                               |
    | status        | string   | Task status (e.g., pending, completed)      |
    | remarks       | string   | Optional notes                              |
    | created_on    | datetime | Creation timestamp                          |
    | updated_on    | datetime | Last updated timestamp                      |

---

- **Approach:** Code-First (Firestore documents are defined via Python logic and js, not SQL).
- **Firestore Indexes** Firestore auto-creates indexes for all single fields.
---
##Live link- https://betsito.com/
## 🚀 Getting Started

Follow these steps to run Focusly locally.

### 1️⃣ Clone the repository
```bash
git clone https://github.com/shivansshhhh/focusly.git
cd focusly
```
### 2️⃣ Create a virtual environment
```bash
python -m venv venv
venv\Scripts\activate   # Windows
source venv/bin/activate # Mac/Linux
```
### 3️⃣ Install dependencies
```bash
pip install -r requirements.txt
```
### 4️⃣ Setup Firebase & Google OAuth Credentials
🔹 Firebase

    Create a Firebase project.

    Enable Authentication → Email, Google & Phone Sign-in.

    Download your Admin SDK JSON and save it as:

    firebase_key.json

### 5️⃣ Add a firebase_key.json file paste all details

{
  "type": "service_account",
  "project_id": "your-project-id",
  "private_key_id": "your-private-key-id",
  "private_key": "-----BEGIN PRIVATE KEY-----\nYOUR-PRIVATE-KEY\n-----END PRIVATE KEY-----\n",
  "client_email": "your-service-account@your-project-id.iam.gserviceaccount.com",
  "client_id": "your-client-id",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/your-service-account%40your-project-id.iam.gserviceaccount.com",
  "universe_domain": "googleapis.com"
}

### 6️⃣ Run the app
```bash
cd backend
python app.py
```
Now all set.
Visit 👉 http://127.0.0.1:5000


📂 Project Structure
```
focusly/
│── backend/
│   ├── app.py                # Main Flask app
│   ├── focusly-firebase-adminsdk.json
│   ├── templates/            # Jinja2 templates (HTML)
│   │    ├── index.html
│   │    ├── login.html
│   │    ├── register.html
│   │    ├── dashboard.html
│   │    └── pomodoro.html and other's
│   └── static/               # videos, and Images
│
├── requirements.txt
├── .env
└── README.md
```
---

## 🌐 Deployment Architecture

![Deployment Architecture](deployment_architecture.png)

### Domain & Hosting Details

The app is deployed on a privately owned domain using a Germany-based VPS for full control over deployment and performance.

- **Domain**: [https://betsito.com](https://betsito.com)
- **Registrar**: Njalla
- **Server Location**: Germany
- **SSL**: Enabled via Let's Encrypt
- **Firewall**: UFW with allowed ports for HTTP/HTTPS

This setup ensures better control over infrastructure, performance, and security.
---


## ⚙️ User Acceptance Testing (UAT)

The app was manually tested to ensure readiness for production:

✅ Register/Login using Email/Password  
✅ Login with Phone OTP (Firebase)  
✅ Add/Edit/Delete/Update Tasks  
✅ Pomodoro Timer Functionality  
✅ Cross-browser checks (Chrome, Firefox, Edge)  
✅ Responsive Design on Mobile and Desktop  
✅ Firebase rules verified for security

No critical bugs found at the time of testing.

try-

use id- top@gmail.com, 
password- 1234567890 (only for testing and review the web app in condition sign up not working.)

---
👨‍💻 Author

Shivansh Panwar
📧 shivanshpawar7448@gmail.com
🌐 https://www.linkedin.com/in/shivansh-d-p/


    ⚡ “Focusly doesn’t just manage your tasks — it manages your time, your goals, and your life.”


---
