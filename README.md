# 📄 Contract Management System

This is a Kotlin + Spring Boot-based application for managing and generating contracts using templates. Users can assign operators, fill out values, generate DOCX/PDF files, and download documents in ZIP format.

## 🚀 Features

- 🔐 Role-based authentication (Operator, Director,ADMIN,USER etc.)
- 📝 Template-based contract generation
- 📎 Assign contracts to multiple operators
- 📂 DOCX → PDF and conversion (LibreOffice)
- 📦 Download multiple files as ZIP
- 🌐 Multi-language error messages (`Accept-Language` support)
- 📊 Filter/search by name, status, etc.

## ⚙️ Technologies Used

- Kotlin
- Spring Boot
- Spring Security
- JPA / Hibernate
- PostgreSQL
- LibreOffice CLI (for document conversion)

## 🔧 Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/asadullanormengliyev/springboot-contract-generator
   cd springboot-contract-generator
