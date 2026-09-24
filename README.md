# CyberSafe Quiz

A simple web-based **Cybersecurity Awareness Quiz System** developed using **Python Flask** and **MySQL**. The application helps users test their basic cybersecurity knowledge through interactive quizzes.

## Project Overview

CyberSafe Quiz is a Flask-based web application designed to provide a simple and user-friendly cybersecurity awareness quiz.

The system allows users to:

- Create an account
- Login securely
- Access a dashboard
- View cybersecurity quiz questions
- Take cybersecurity quizzes
- Submit answers
- View quiz scores
- Store quiz attempts in MySQL
- Manage quiz questions using CRUD operations

## Features

### 1. User Registration

Users can create an account using:

- Username
- Email
- Password

Passwords are securely hashed before being stored in the database.

### 2. User Login & Authentication

Registered users can login using their email and password.

The application uses Flask sessions to maintain authenticated users.

### 3. Dashboard

The dashboard provides an overview of:

- Total questions
- Total registered users
- Quiz attempts
- Available quiz functions

### 4. Cybersecurity Quiz

Users can answer questions related to cybersecurity topics such as:

- Phishing
- Malware
- Password Security
- Multi-Factor Authentication
- Firewalls

After submitting the quiz, the system calculates and displays the user's score.

### 5. Question Management

The application supports CRUD operations for quiz questions.

CRUD stands for:

- **Create** – Add new questions
- **Read** – View existing questions
- **Update** – Edit questions
- **Delete** – Remove questions

### 6. MySQL Database

The application uses MySQL to store:

- User information
- Quiz questions
- Quiz attempts and scores

The database is managed using **XAMPP and phpMyAdmin**.

## Technologies Used

| Technology | Purpose |
|---|---|
| Python | Backend programming |
| Flask | Web application framework |
| MySQL | Database |
| XAMPP | Local MySQL environment |
| phpMyAdmin | Database management |
| HTML | Web page structure |
| CSS | User interface design |
| Werkzeug | Password hashing |
| Git & GitHub | Version control and project hosting |

## Project Structure

```text
CyberSafeQuiz/
│
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
│
├── templates/
│   ├── base.html
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── quiz.html
│   ├── result.html
│   ├── questions.html
│   ├── add_question.html
│   └── edit_question.html
│
└── static/
    └── style.css
