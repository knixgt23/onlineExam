# EduAssess - Online Examination Portal

## Prerequisites

- Python 3.8+
- Oracle Database (Express Edition or higher)
- Requirements.txt

## Database Setup

### Step 1: Install Oracle Database

Download and install Oracle Database XE from:
https://www.oracle.com/database/technologies/xe-downloads.html

### Step 2: Run SQL Schema

1. Open SQL Developer
2. Connect to your Oracle database
3. Open the file `DB.sql`
4. Run all the SQL commands (F5)

### Step 3: Create Database User
```sql
-- Connect as SYSTEM
CREATE USER C##exam_admin IDENTIFIED BY exam_password_123;
GRANT CONNECT, RESOURCE, DBA TO C##exam_admin;
GRANT UNLIMITED TABLESPACE TO C##exam_admin;
COMMIT;
```

##Running the APP
1.Run main.py (runs the backend)
2.Run login.html (runs the frontend)