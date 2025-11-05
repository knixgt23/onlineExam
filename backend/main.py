from datetime import datetime, timedelta
from functools import wraps
import jwt
from Secret_info_dont_upload_this_in_deployment import CONFIG,JWT_KEY
from flask import Flask,request,jsonify
from flask_cors import CORS
import cx_Oracle
from werkzeug.security import generate_password_hash, check_password_hash


app=Flask(__name__)
CORS(app)

app.config['JWT_SECRET_KEY'] = JWT_KEY

ORACLE_CONFIG=CONFIG



# JWT Token verification decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')

        if not token:
            return jsonify({'status': 'error', 'message': 'Token is missing'}), 401

        try:
            if token.startswith('Bearer '):
                token = token.split(' ')[1]

            data = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
            current_user = data
        except jwt.ExpiredSignatureError:
            return jsonify({'status': 'error', 'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'status': 'error', 'message': 'Invalid token'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

#connect DB
def get_db_connection():
    try:
        connection=cx_Oracle.connect(**ORACLE_CONFIG)
        return connection
    except cx_Oracle.Error as error:
        print(f"DB connection error: {error}")
        return None


@app.route('/api/register',methods=['POST'])
def register():
    print("-"*60)
    print("New registration request")
    print("-"*60)

    data=request.get_json()
    print(f"Email: {data.get('email')}")
    print(f"Name: {data.get('full_name')}")
    print(f"Type: {data.get('user_type')}")

    # Validate required fields
    if not data.get('email'):
        return jsonify({'status': 'error', 'message': 'Email is required'}), 400

    if not data.get('password'):
        return jsonify({'status': 'error', 'message': 'Password is required'}), 400

    if not data.get('full_name'):
        return jsonify({'status': 'error', 'message': 'Full name is required'}), 400

    # Validate user type specific fields
    user_type = data.get('user_type', 'STUDENT').upper()

    if user_type == 'STUDENT' and not data.get('roll_number'):
        return jsonify({'status': 'error', 'message': 'Roll number is required for students'}), 400

    if user_type == 'TEACHER' and not data.get('employee_id'):
        return jsonify({'status': 'error', 'message': 'Employee ID is required for teachers'}), 400



    #Connect db
    conn=get_db_connection()
    if not conn:
        return jsonify({'status':'error','message':'Db connection failed'})

    try:
        cursor=conn.cursor()

        #hash password
        password_hash=generate_password_hash(data['password'])
        print("Password hashed!")

        #Output vars
        user_id=cursor.var(cx_Oracle.NUMBER)
        status=cursor.var(cx_Oracle.STRING)
        message=cursor.var(cx_Oracle.STRING)


        print("Calling proc: sp_register_user")

        #call the proc
        cursor.callproc('sp_register_user',[
            data['email'],
            password_hash,
            data['full_name'],
            user_type,
            data.get('phone_number'),
            data.get('roll_number'),
            data.get('employee_id'),
            data.get('department'),
            user_id,
            status,
            message
        ])

        conn.commit()
        print("Proc commited")

        #Results
        final_status=status.getvalue()
        final_message=message.getvalue()
        final_user_id=user_id.getvalue()

        print(f"Status: {final_status}")
        print(f"Message: {final_message}")
        print(f"User ID: {final_user_id}")
        print("-"*60)


        if final_status=="SUCCESS":
            return jsonify({
                'status':'success',
                'message':final_message,
                'user_id':final_user_id
            }),201
        else:
            return jsonify({
                'status':'error',
                'message':final_message
            }),400

    except cx_Oracle.Error as error:
        conn.rollback()
        print(f"DB error: {error}")
        print('-'*60)
        return jsonify({
            'status': 'error',
            'message': f'Database error: {str(error)}'
        }), 500

    finally:
        cursor.close()
        conn.close()


@app.route('/api/login',methods=['POST'])
def login():
    print('-'*60)
    print("New login request")
    print('-'*60)

    data=request.get_json()
    print(f"Email: {data.get('email')}")


    #validate fields
    if not data.get('email'):
        return jsonify({'status':'error','message':'Email is required'}),400
    if not data.get('password'):
        return jsonify({'status':'error','message':'Password is required'}),400

    conn=get_db_connection()
    if not conn:
        return jsonify({'status':'error','message':'DB connection failed'}),500
    try:
        cursor=conn.cursor()
        print("Searching for user in DB")
        cursor.execute("""
                    SELECT 
                        u.user_id,
                        u.email,
                        u.password_hash,
                        u.full_name,
                        u.user_type,
                        s.student_id,
                        t.teacher_id,
                        a.admin_id,
                        s.roll_number,
                        t.employee_id,
                        s.department,
                        u.phone_number
                    FROM users u
                    LEFT JOIN students s ON u.user_id = s.user_id
                    LEFT JOIN teachers t ON u.user_id = t.user_id
                    LEFT JOIN admins a ON u.user_id = a.user_id
                    WHERE u.email = :email AND u.is_active = 1
                """, email=data['email'])

        user=cursor.fetchone()

        if not user:
            print("User not found")
            return jsonify({
                'status':'error',
                'message':'Invalid email or password'
            }),401

        print(f"User found: {user[3]} ({user[4]})")

        #verify pass
        password_is_correct=check_password_hash(user[2],data['password'])

        if not password_is_correct:
            print("Password incorrect")
            return jsonify({
                'status':'error',
                'message':'Invalid email or password'
            }),401

        print("Password verified")

        #Determine role_id(student,teacher,admin)
        role_id=user[5] or user[6] or user[7]


        #create JWT token
        token_payload={
            'user_id':user[0],
            'email':user[1],
            'full_name':user[3],
            'user_type': user[4],
            'role_id': role_id,
            'exp': datetime.utcnow() + timedelta(hours=24)
        }

        print("Creating JWT token...")


        token=jwt.encode(
            token_payload,
            app.config['JWT_SECRET_KEY'],
            algorithm='HS256'
        )


        print('Token created successfully')

        #Update last login
        cursor.execute("""
        UPDATE users
        SET last_login=CURRENT_TIMESTAMP
        WHERE user_id=:user_id""",user_id=user[0])

        conn.commit()

        print(f"Login successful for: {user[3]}")
        print('-'*60)

        #return response
        return jsonify({
            'status': 'success',
            'message': 'Login successful',
            'token': token,
            'user': {
                'user_id': user[0],
                'email': user[1],
                'full_name': user[3],
                'user_type': user[4],
                'role_id': role_id,
                'roll_number': user[8] if user[4] == 'STUDENT' else None,
                'employee_id': user[9] if user[4] == 'TEACHER' else None,
                'department': user[10],
                'phone_number': user[11]
            }
        }), 200
    except cx_Oracle.Error as error:
        print(f"❌ Database error: {error}")
        print("=" * 60 + "\n")
        return jsonify({
            'status': 'error',
            'message': f'Database error: {str(error)}'
        }), 500

    finally:
        cursor.close()
        conn.close()


#Get available exams for student
@app.route('/api/student/exams/<int:student_id>', methods=['GET'])
@token_required
def get_student_exams(current_user, student_id):
    print('-' * 60)
    print(f"Fetching exams for student: {student_id}")
    print('-' * 60)

    # verify student_id matches token
    if current_user.get('role_id') != student_id:
        return jsonify({'status': 'error', 'message': 'Unauthorized access'}), 403

    # DB connection
    conn = get_db_connection()
    if not conn:
        return jsonify({'status': 'error', 'message': 'DB connection failed'}), 500

    try:
        cursor = conn.cursor()

        # get available exams for the student
        cursor.execute("""
                    SELECT 
                        e.exam_id,
                        e.exam_title,
                        e.exam_description,
                        e.subject,
                        e.total_marks,
                        e.duration_minutes,
                        e.scheduled_date,
                        e.end_date,
                        e.instructions,
                        u.full_name as teacher_name,
                        ee.is_eligible,
                        CASE 
                            WHEN CURRENT_TIMESTAMP < e.scheduled_date THEN 'UPCOMING'
                            WHEN CURRENT_TIMESTAMP BETWEEN e.scheduled_date AND e.end_date THEN 'ACTIVE'
                            ELSE 'EXPIRED'
                        END as exam_status,
                        (SELECT COUNT(*) FROM exam_sessions es 
                         WHERE es.exam_id = e.exam_id 
                         AND es.student_id = :student_id) as has_attempted
                    FROM exams e
                    JOIN teachers t ON e.teacher_id = t.teacher_id
                    JOIN users u ON t.user_id = u.user_id
                    LEFT JOIN exam_enrollments ee ON e.exam_id = ee.exam_id 
                        AND ee.student_id = :student_id
                    WHERE e.is_published = 1
                    AND (ee.student_id = :student_id OR ee.student_id IS NULL)
                    ORDER BY e.scheduled_date ASC
                """, student_id=student_id)

        exams = []
        for row in cursor.fetchall():
            # Convert CLOB to string - this is the key fix
            instructions_text = row[8].read() if row[8] is not None else None
            exam_desc_text = row[2].read() if row[2] is not None else None

            exams.append({
                'exam_id': row[0],
                'exam_title': row[1],
                'exam_description': exam_desc_text,  # Fixed
                'subject': row[3],
                'total_marks': row[4],
                'duration_minutes': row[5],
                'scheduled_date': row[6].isoformat() if row[6] else None,
                'end_date': row[7].isoformat() if row[7] else None,
                'instructions': instructions_text,  # Fixed
                'teacher_name': row[9],
                'is_eligible': bool(row[10]) if row[10] is not None else False,
                'exam_status': row[11],
                'has_attempted': row[12] > 0
            })

        print(f"Found {len(exams)} exams")
        print('-' * 60)
        return jsonify({
            'status': 'success',
            'exams': exams
        }), 200

    except cx_Oracle.Error as error:
        print(f"DB error: {error}")
        return jsonify({'status': 'error', 'message': str(error)}), 500

    finally:
        cursor.close()
        conn.close()


#student results
@app.route('/api/student/results/<int:student_id>', methods=['GET'])
@token_required
def get_student_results(current_user, student_id):
    print('-'*60)
    print(f"Fetching results for student: {student_id}")
    print('-'*60)

    if current_user.get('role_id')!=student_id:
        return jsonify({'status': 'error', 'message': 'Unauthorized access'}), 403

    conn = get_db_connection()
    if not conn:
        return jsonify({'status': 'error', 'message': 'DB connection failed'}), 500

    try:
        cursor = conn.cursor()

        cursor.execute("""
                SELECT 
                    er.result_id,
                    er.exam_id,
                    e.exam_title,
                    e.subject,
                    er.total_marks_obtained,
                    e.total_marks,
                    er.percentage,
                    er.grade,
                    er.status,
                    er.rank_in_exam,
                    er.evaluated_at,
                    es.actual_duration_minutes,
                    (SELECT COUNT(*) FROM proctoring_logs pl 
                     WHERE pl.session_id = es.session_id) as proctoring_incidents
                FROM exam_results er
                JOIN exams e ON er.exam_id = e.exam_id
                JOIN exam_sessions es ON er.session_id = es.session_id
                WHERE er.student_id = :student_id
                ORDER BY er.evaluated_at DESC
            """, student_id=student_id)

        results = []
        for row in cursor.fetchall():
            results.append({
                'result_id': row[0],
                'exam_id': row[1],
                'exam_title': row[2],
                'subject': row[3],
                'marks_obtained': row[4],
                'total_marks': row[5],
                'percentage': float(row[6]) if row[6] else 0,
                'grade': row[7],
                'status': row[8],
                'rank': row[9],
                'evaluated_at': row[10].isoformat() if row[10] else None,
                'duration_taken': row[11],
                'proctoring_incidents': row[12]
            })

        print(f"Found {len(results)} results")
        print('-' * 60)

        return jsonify({
            'status': 'success',
            'results': results
        }), 200

    except cx_Oracle.Error as error:
        print(f"DB error: {error}")
        return jsonify({'status': 'error', 'message': str(error)}), 500
    finally:
        cursor.close()
        conn.close()


#Student stats
@app.route('/api/student/stats/<int:student_id>', methods=['GET'])
@token_required
def get_student_stats(current_user, student_id):
    print('-' * 60)
    print(f"Fetching stats for student: {student_id}")
    print('-' * 60)

    if current_user.get('role_id') != student_id:
        return jsonify({'status': 'error', 'message': 'Unauthorized access'}), 403

    conn = get_db_connection()
    if not conn:
        return jsonify({'status': 'error', 'message': 'DB connection failed'}), 500

    try:
        cursor = conn.cursor()

        # Get overall statistics
        cursor.execute("""
            SELECT 
                COUNT(*) as total_exams,
                COUNT(CASE WHEN status = 'PASS' THEN 1 END) as passed_exams,
                COUNT(CASE WHEN status = 'FAIL' THEN 1 END) as failed_exams,
                AVG(percentage) as avg_percentage,
                MAX(percentage) as highest_percentage,
                MIN(percentage) as lowest_percentage
            FROM exam_results
            WHERE student_id = :student_id
        """, student_id=student_id)

        stats_row = cursor.fetchone()

        # Get available exams count
        cursor.execute("""
            SELECT COUNT(*) 
            FROM exams e
            LEFT JOIN exam_enrollments ee ON e.exam_id = ee.exam_id 
                AND ee.student_id = :student_id
            WHERE e.is_published = 1
            AND CURRENT_TIMESTAMP BETWEEN e.scheduled_date AND e.end_date
            AND NOT EXISTS (
                SELECT 1 FROM exam_sessions es 
                WHERE es.exam_id = e.exam_id 
                AND es.student_id = :student_id
            )
        """, student_id=student_id)

        available_count = cursor.fetchone()[0]

        # Get upcoming exams count
        cursor.execute("""
            SELECT COUNT(*) 
            FROM exams e
            LEFT JOIN exam_enrollments ee ON e.exam_id = ee.exam_id 
                AND ee.student_id = :student_id
            WHERE e.is_published = 1
            AND CURRENT_TIMESTAMP < e.scheduled_date
        """, student_id=student_id)

        upcoming_count = cursor.fetchone()[0]

        stats = {
            'total_exams_taken': stats_row[0] or 0,
            'passed_exams': stats_row[1] or 0,
            'failed_exams': stats_row[2] or 0,
            'average_percentage': float(stats_row[3]) if stats_row[3] else 0,
            'highest_percentage': float(stats_row[4]) if stats_row[4] else 0,
            'lowest_percentage': float(stats_row[5]) if stats_row[5] else 0,
            'available_exams': available_count or 0,
            'upcoming_exams': upcoming_count or 0
        }

        print(f"Stats: {stats}")
        print('-' * 60)

        return jsonify({
            'status': 'success',
            'stats': stats
        }), 200

    except cx_Oracle.Error as error:
        print(f"DB error: {error}")
        return jsonify({'status': 'error', 'message': str(error)}), 500
    finally:
        cursor.close()
        conn.close()


#Get Exam Details (for starting exam)
@app.route('/api/student/exam/<int:exam_id>/details', methods=['GET'])
@token_required
def get_student_exam_details(current_user, exam_id):
    print('-' * 60)
    print(f"Fetching exam details: {exam_id}")
    print('-' * 60)

    conn = get_db_connection()
    if not conn:
        return jsonify({'status': 'error', 'message': 'DB connection failed'}), 500

    try:
        cursor = conn.cursor()

        # Get exam details
        cursor.execute("""
            SELECT 
                e.exam_id,
                e.exam_title,
                e.exam_description,
                e.subject,
                e.total_marks,
                e.duration_minutes,
                e.scheduled_date,
                e.end_date,
                e.instructions,
                e.full_screen_required,
                e.dual_camera_required,
                e.tab_switch_allowed,
                u.full_name as teacher_name,
                (SELECT COUNT(*) FROM questions q WHERE q.exam_id = e.exam_id) as question_count
            FROM exams e
            JOIN teachers t ON e.teacher_id = t.teacher_id
            JOIN users u ON t.user_id = u.user_id
            WHERE e.exam_id = :exam_id
        """, exam_id=exam_id)

        row = cursor.fetchone()

        if not row:
            return jsonify({'status': 'error', 'message': 'Exam not found'}), 404

        # Convert CLOB fields to strings
        exam_desc = row[2].read() if row[2] is not None else None
        instructions = row[8].read() if row[8] is not None else None

        exam_details = {
            'exam_id': row[0],
            'exam_title': row[1],
            'exam_description': exam_desc,  # Fixed
            'subject': row[3],
            'total_marks': row[4],
            'duration_minutes': row[5],
            'scheduled_date': row[6].isoformat() if row[6] else None,
            'end_date': row[7].isoformat() if row[7] else None,
            'instructions': instructions,  # Fixed
            'full_screen_required': bool(row[9]),
            'dual_camera_required': bool(row[10]),
            'tab_switch_allowed': bool(row[11]),
            'teacher_name': row[12],
            'question_count': row[13]
        }

        print(f"Exam details retrieved successfully")
        print('-' * 60)

        return jsonify({
            'status': 'success',
            'exam': exam_details
        }), 200

    except cx_Oracle.Error as error:
        print(f"DB error: {error}")
        return jsonify({'status': 'error', 'message': str(error)}), 500
    finally:
        cursor.close()
        conn.close()


#Enroll in Exam (if not auto-enrolled)
@app.route('/api/student/exam/<int:exam_id>/enroll', methods=['POST'])
@token_required
def enroll_in_exam(current_user, exam_id):
    print('-' * 60)
    print(f"Enrollment request for exam: {exam_id}")
    print('-' * 60)

    student_id = current_user.get('role_id')

    conn = get_db_connection()
    if not conn:
        return jsonify({'status': 'error', 'message': 'DB connection failed'}), 500

    try:
        cursor = conn.cursor()

        # Output variables
        status = cursor.var(cx_Oracle.STRING)
        message = cursor.var(cx_Oracle.STRING)

        # Call stored procedure
        cursor.callproc('sp_enroll_student', [
            exam_id,
            student_id,
            status,
            message
        ])

        conn.commit()

        final_status = status.getvalue()
        final_message = message.getvalue()

        print(f"Status: {final_status}")
        print(f"Message: {final_message}")
        print('-' * 60)

        if final_status == 'SUCCESS':
            return jsonify({
                'status': 'success',
                'message': final_message
            }), 200
        else:
            return jsonify({
                'status': 'error',
                'message': final_message
            }), 400

    except cx_Oracle.Error as error:
        conn.rollback()
        print(f"DB error: {error}")
        return jsonify({'status': 'error', 'message': str(error)}), 500
    finally:
        cursor.close()
        conn.close()


# 1. Create Exam
@app.route('/api/teacher/exam/create', methods=['POST'])
@token_required
def create_exam(current_user):
    print('-' * 60)
    print("Create exam request")
    print('-' * 60)

    data = request.get_json()
    teacher_id = current_user.get('role_id')

    print(f"Received data: {data}")
    print(f"Teacher ID: {teacher_id}")

    # Validate required fields
    required_fields = ['exam_title', 'subject', 'total_marks', 'duration_minutes',
                       'scheduled_date', 'end_date']

    for field in required_fields:
        if not data.get(field):
            return jsonify({'status': 'error', 'message': f'{field} is required'}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({'status': 'error', 'message': 'DB connection failed'}), 500

    try:
        cursor = conn.cursor()

        # Convert datetime strings to proper format
        scheduled_dt = datetime.fromisoformat(data['scheduled_date'].replace('Z', '+00:00'))
        end_dt = datetime.fromisoformat(data['end_date'].replace('Z', '+00:00'))

        # Create Oracle Timestamp objects
        scheduled_date = cx_Oracle.Timestamp(scheduled_dt.year, scheduled_dt.month, scheduled_dt.day,
                                             scheduled_dt.hour, scheduled_dt.minute, scheduled_dt.second)
        end_date = cx_Oracle.Timestamp(end_dt.year, end_dt.month, end_dt.day,
                                       end_dt.hour, end_dt.minute, end_dt.second)

        print(f"Converted scheduled_date: {scheduled_date}")
        print(f"Converted end_date: {end_date}")

        # Calculate pass_marks if not provided
        pass_marks = data.get('pass_marks')
        if not pass_marks:
            pass_marks = int(data['total_marks'] * 0.4)

        # Output variables
        exam_id = cursor.var(cx_Oracle.NUMBER)
        status = cursor.var(cx_Oracle.STRING)
        message = cursor.var(cx_Oracle.STRING)

        # Prepare parameters
        instructions = data.get('instructions', '').strip()
        description = data.get('exam_description', '').strip()

        params = [
            teacher_id,
            data['exam_title'],
            description if description else None,  # Changed
            data['subject'],
            int(data['total_marks']),
            int(pass_marks),
            int(data['duration_minutes']),
            scheduled_date,
            end_date,
            instructions if instructions else None,  # Changed
            exam_id,
            status,
            message
        ]

        # Call stored procedure
        print(f"Total parameters: {len(params)}")
        cursor.callproc('sp_create_exam', params)

        conn.commit()

        final_status = status.getvalue()
        final_message = message.getvalue()
        final_exam_id = exam_id.getvalue()

        print(f"Status: {final_status}")
        print(f"Message: {final_message}")
        print(f"Exam ID: {final_exam_id}")

        # Update exam settings
        if final_status == 'SUCCESS' and final_exam_id:
            cursor.execute("""
                UPDATE exams 
                SET full_screen_required = :fullscreen,
                    dual_camera_required = :camera,
                    tab_switch_allowed = :tabswitch
                WHERE exam_id = :exam_id
            """, {
                'fullscreen': 1 if data.get('full_screen_required') else 0,
                'camera': 1 if data.get('dual_camera_required') else 0,
                'tabswitch': 1 if data.get('tab_switch_allowed') else 0,
                'exam_id': final_exam_id
            })
            conn.commit()

        print('-' * 60)

        if final_status == 'SUCCESS':
            return jsonify({
                'status': 'success',
                'message': final_message,
                'exam_id': final_exam_id
            }), 201
        else:
            return jsonify({
                'status': 'error',
                'message': final_message
            }), 400

    except Exception as error:
        conn.rollback()
        print(f"Python error: {error}")
        print(f"Error type: {type(error).__name__}")
        import traceback
        print(f"Traceback:\n{traceback.format_exc()}")
        return jsonify({'status': 'error', 'message': str(error)}), 500
    finally:
        cursor.close()
        conn.close()


# 2. Add Question to Exam
@app.route('/api/teacher/exam/<int:exam_id>/question', methods=['POST'])
@token_required
def add_question(current_user, exam_id):
    print('-' * 60)
    print(f"Adding question to exam: {exam_id}")
    print('-' * 60)

    data = request.get_json()

    print(f"📝 Question data received:")
    print(f"  Text: {data.get('question_text')[:50]}...")
    print(f"  Type: {data.get('question_type')}")
    print(f"  Marks: {data.get('marks')}")
    print(f"  Options count: {len(data.get('options', []))}")

    if not data.get('question_text'):
        return jsonify({'status': 'error', 'message': 'Question text is required'}), 400

    if not data.get('question_type'):
        return jsonify({'status': 'error', 'message': 'Question type is required'}), 400

    if not data.get('marks'):
        return jsonify({'status': 'error', 'message': 'Marks is required'}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({'status': 'error', 'message': 'DB connection failed'}), 500

    try:
        cursor = conn.cursor()

        # Output variables
        question_id = cursor.var(cx_Oracle.NUMBER)
        status = cursor.var(cx_Oracle.STRING)
        message = cursor.var(cx_Oracle.STRING)

        # Call stored procedure
        cursor.callproc('sp_add_question', [
            exam_id,
            data['question_text'],
            data['question_type'],
            data['marks'],
            data.get('question_order', 1),
            question_id,
            status,
            message
        ])

        conn.commit()

        final_status = status.getvalue()
        final_message = message.getvalue()
        final_question_id = question_id.getvalue()

        print(f"✅ Question ID: {final_question_id}")

        # If MCQ, add options
        if final_status == 'SUCCESS' and data['question_type'] in ['MCQ', 'TRUE_FALSE']:
            options = data.get('options', [])
            print(f"📋 Adding {len(options)} options...")

            for opt in options:
                print(
                    f"  Adding option {opt['option_order']}: {opt['option_text'][:30]}... (correct: {opt.get('is_correct')})")

                opt_status = cursor.var(cx_Oracle.STRING)
                opt_message = cursor.var(cx_Oracle.STRING)

                try:
                    cursor.callproc('sp_add_mcq_option', [
                        final_question_id,
                        opt['option_text'],
                        opt['option_order'],
                        1 if opt.get('is_correct') else 0,
                        opt_status,
                        opt_message
                    ])

                    opt_final_status = opt_status.getvalue()
                    opt_final_message = opt_message.getvalue()

                    print(f"    Status: {opt_final_status}")
                    print(f"    Message: {opt_final_message}")

                except Exception as e:
                    print(f"    ❌ Exception: {str(e)}")

            conn.commit()
            print(f"✅ Options commit completed")

        print('-' * 60)

        if final_status == 'SUCCESS':
            return jsonify({
                'status': 'success',
                'message': final_message,
                'question_id': final_question_id
            }), 201
        else:
            return jsonify({
                'status': 'error',
                'message': final_message
            }), 400

    except cx_Oracle.Error as error:
        conn.rollback()
        print(f"❌ DB error: {error}")
        import traceback
        print(traceback.format_exc())
        return jsonify({'status': 'error', 'message': str(error)}), 500
    finally:
        cursor.close()
        conn.close()


# 3. Get Teacher's Exams
@app.route('/api/teacher/exams', methods=['GET'])
@token_required
def get_teacher_exams(current_user):
    print('-' * 60)
    print(f"Fetching exams for teacher: {current_user.get('role_id')}")
    print('-' * 60)

    teacher_id = current_user.get('role_id')

    conn = get_db_connection()
    if not conn:
        return jsonify({'status': 'error', 'message': 'DB connection failed'}), 500

    try:
        cursor = conn.cursor()

        cursor.execute("""
            SELECT 
                e.exam_id,
                e.exam_title,
                e.exam_description,
                e.subject,
                e.total_marks,
                e.duration_minutes,
                e.scheduled_date,
                e.end_date,
                e.is_published,
                e.created_at,
                (SELECT COUNT(*) FROM questions q WHERE q.exam_id = e.exam_id) as question_count,
                (SELECT COUNT(*) FROM exam_enrollments ee WHERE ee.exam_id = e.exam_id) as enrolled_count,
                (SELECT COUNT(*) FROM exam_sessions es WHERE es.exam_id = e.exam_id AND es.status = 'COMPLETED') as completed_count,
                CASE 
                    WHEN CURRENT_TIMESTAMP < e.scheduled_date THEN 'UPCOMING'
                    WHEN CURRENT_TIMESTAMP BETWEEN e.scheduled_date AND e.end_date THEN 'ACTIVE'
                    ELSE 'EXPIRED'
                END as exam_status
            FROM exams e
            WHERE e.teacher_id = :teacher_id
            ORDER BY e.scheduled_date DESC
        """, teacher_id=teacher_id)

        exams = []
        for row in cursor.fetchall():
            exams.append({
                'exam_id': row[0],
                'exam_title': row[1],
                'exam_description': row[2],
                'subject': row[3],
                'total_marks': row[4],
                'duration_minutes': row[5],
                'scheduled_date': row[6].isoformat() if row[6] else None,
                'end_date': row[7].isoformat() if row[7] else None,
                'is_published': bool(row[8]),
                'created_at': row[9].isoformat() if row[9] else None,
                'question_count': row[10],
                'enrolled_count': row[11],
                'completed_count': row[12],
                'exam_status': row[13]
            })

        print(f"Found {len(exams)} exams")
        print('-' * 60)

        return jsonify({
            'status': 'success',
            'exams': exams
        }), 200

    except cx_Oracle.Error as error:
        print(f"DB error: {error}")
        return jsonify({'status': 'error', 'message': str(error)}), 500
    finally:
        cursor.close()
        conn.close()


# 4. Get Exam Details with Questions
@app.route('/api/teacher/exam/<int:exam_id>', methods=['GET'])
@token_required
def get_teacher_exam_details(current_user, exam_id):
    print('-' * 60)
    print(f"Fetching exam details: {exam_id}")
    print('-' * 60)

    conn = get_db_connection()
    if not conn:
        return jsonify({'status': 'error', 'message': 'DB connection failed'}), 500

    try:
        cursor = conn.cursor()

        # Get exam details
        cursor.execute("""
            SELECT 
                e.exam_id,
                e.exam_title,
                e.exam_description,
                e.subject,
                e.total_marks,
                e.duration_minutes,
                e.scheduled_date,
                e.end_date,
                e.is_published,
                e.full_screen_required,
                e.dual_camera_required,
                e.tab_switch_allowed,
                e.pass_marks,
                e.instructions
            FROM exams e
            WHERE e.exam_id = :exam_id
        """, exam_id=exam_id)

        exam_row = cursor.fetchone()

        if not exam_row:
            return jsonify({'status': 'error', 'message': 'Exam not found'}), 404

        # Convert CLOB fields to strings
        exam_desc = exam_row[2].read() if exam_row[2] is not None else None
        instructions = exam_row[13].read() if exam_row[13] is not None else None

        # Get questions
        cursor.execute("""
            SELECT 
                q.question_id,
                q.question_text,
                q.question_type,
                q.marks,
                q.question_order
            FROM questions q
            WHERE q.exam_id = :exam_id
            ORDER BY q.question_order
        """, exam_id=exam_id)

        questions = []
        for q_row in cursor.fetchall():
            # Convert question text CLOB to string
            question_text = q_row[1].read() if q_row[1] is not None else None

            question = {
                'question_id': q_row[0],
                'question_text': question_text,  # Fixed
                'question_type': q_row[2],
                'marks': q_row[3],
                'question_order': q_row[4],
                'options': []
            }

            # Get options if MCQ
            if q_row[2] in ['MCQ', 'TRUE_FALSE']:
                cursor.execute("""
                    SELECT option_id, option_text, option_order, is_correct
                    FROM mcq_options
                    WHERE question_id = :question_id
                    ORDER BY option_order
                """, question_id=q_row[0])

                for opt_row in cursor.fetchall():
                    question['options'].append({
                        'option_id': opt_row[0],
                        'option_text': opt_row[1],
                        'option_order': opt_row[2],
                        'is_correct': bool(opt_row[3])
                    })

            questions.append(question)

        exam = {
            'exam_id': exam_row[0],
            'exam_title': exam_row[1],
            'exam_description': exam_desc,  # Fixed
            'subject': exam_row[3],
            'total_marks': exam_row[4],
            'duration_minutes': exam_row[5],
            'scheduled_date': exam_row[6].isoformat() if exam_row[6] else None,
            'end_date': exam_row[7].isoformat() if exam_row[7] else None,
            'is_published': bool(exam_row[8]),
            'full_screen_required': bool(exam_row[9]),
            'dual_camera_required': bool(exam_row[10]),
            'tab_switch_allowed': bool(exam_row[11]),
            'pass_marks': exam_row[12],
            'instructions': instructions,  # Fixed
            'questions': questions
        }

        print(f"Exam retrieved with {len(questions)} questions")
        print('-' * 60)

        return jsonify({
            'status': 'success',
            'exam': exam
        }), 200

    except cx_Oracle.Error as error:
        print(f"DB error: {error}")
        return jsonify({'status': 'error', 'message': str(error)}), 500
    finally:
        cursor.close()
        conn.close()


# 5. Publish Exam
@app.route('/api/teacher/exam/<int:exam_id>/publish', methods=['POST'])
@token_required
def publish_exam(current_user, exam_id):
    print('-' * 60)
    print(f"Publishing exam: {exam_id}")
    print('-' * 60)

    conn = get_db_connection()
    if not conn:
        return jsonify({'status': 'error', 'message': 'DB connection failed'}), 500

    try:
        cursor = conn.cursor()

        # Output variables
        status = cursor.var(cx_Oracle.STRING)
        message = cursor.var(cx_Oracle.STRING)

        # Call stored procedure
        cursor.callproc('sp_publish_exam', [
            exam_id,
            status,
            message
        ])

        conn.commit()

        final_status = status.getvalue()
        final_message = message.getvalue()

        print(f"Status: {final_status}")
        print(f"Message: {final_message}")
        print('-' * 60)

        if final_status == 'SUCCESS':
            return jsonify({
                'status': 'success',
                'message': final_message
            }), 200
        else:
            return jsonify({
                'status': 'error',
                'message': final_message
            }), 400

    except cx_Oracle.Error as error:
        conn.rollback()
        print(f"DB error: {error}")
        return jsonify({'status': 'error', 'message': str(error)}), 500
    finally:
        cursor.close()
        conn.close()


# 6. Delete Question
@app.route('/api/teacher/question/<int:question_id>', methods=['DELETE'])
@token_required
def delete_question(current_user, question_id):
    print('-' * 60)
    print(f"Deleting question: {question_id}")
    print('-' * 60)

    conn = get_db_connection()
    if not conn:
        return jsonify({'status': 'error', 'message': 'DB connection failed'}), 500

    try:
        cursor = conn.cursor()

        cursor.execute("DELETE FROM questions WHERE question_id = :question_id",
                       question_id=question_id)

        conn.commit()

        print("Question deleted successfully")
        print('-' * 60)

        return jsonify({
            'status': 'success',
            'message': 'Question deleted successfully'
        }), 200

    except cx_Oracle.Error as error:
        conn.rollback()
        print(f"DB error: {error}")
        return jsonify({'status': 'error', 'message': str(error)}), 500
    finally:
        cursor.close()
        conn.close()


# Get active sessions for teacher monitoring
@app.route('/api/teacher/active-sessions', methods=['GET'])
@token_required
def get_teacher_active_sessions(current_user):
    print('-' * 60)
    print(f"Fetching active sessions for teacher: {current_user.get('role_id')}")
    print('-' * 60)

    teacher_id = current_user.get('role_id')

    conn = get_db_connection()
    if not conn:
        return jsonify({'status': 'error', 'message': 'DB connection failed'}), 500

    try:
        cursor = conn.cursor()

        # Get active exam sessions for this teacher's exams
        cursor.execute("""
            SELECT 
                es.session_id,
                es.exam_id,
                e.exam_title,
                es.student_id,
                u.full_name as student_name,
                st.roll_number,
                es.start_time,
                es.status,
                es.ip_address,
                (SELECT COUNT(*) FROM proctoring_logs pl 
                 WHERE pl.session_id = es.session_id) as proctoring_events,
                (SELECT COUNT(*) FROM proctoring_logs pl 
                 WHERE pl.session_id = es.session_id 
                 AND pl.severity = 'HIGH') as high_severity_events,
                (SELECT COUNT(*) FROM alerts a 
                 WHERE a.session_id = es.session_id 
                 AND a.is_read = 0) as unread_alerts
            FROM exam_sessions es
            JOIN exams e ON es.exam_id = e.exam_id
            JOIN students st ON es.student_id = st.student_id
            JOIN users u ON st.user_id = u.user_id
            WHERE e.teacher_id = :teacher_id
            AND es.status = 'IN_PROGRESS'
            ORDER BY es.start_time DESC
        """, teacher_id=teacher_id)

        sessions = []
        for row in cursor.fetchall():
            sessions.append({
                'session_id': row[0],
                'exam_id': row[1],
                'exam_title': row[2],
                'student_id': row[3],
                'student_name': row[4],
                'roll_number': row[5],
                'start_time': row[6].isoformat() if row[6] else None,
                'status': row[7],
                'ip_address': row[8],
                'proctoring_events': row[9] or 0,
                'high_severity_events': row[10] or 0,
                'unread_alerts': row[11] or 0
            })

        print(f"Found {len(sessions)} active sessions")
        print('-' * 60)

        return jsonify({
            'status': 'success',
            'sessions': sessions
        }), 200

    except cx_Oracle.Error as error:
        print(f"DB error: {error}")
        return jsonify({'status': 'error', 'message': str(error)}), 500
    finally:
        cursor.close()
        conn.close()

# 7. Update Exam
@app.route('/api/teacher/exam/<int:exam_id>', methods=['PUT'])
@token_required
def update_exam(current_user, exam_id):
    print('-' * 60)
    print(f"Updating exam: {exam_id}")
    print('-' * 60)

    data = request.get_json()

    conn = get_db_connection()
    if not conn:
        return jsonify({'status': 'error', 'message': 'DB connection failed'}), 500

    try:
        cursor = conn.cursor()

        # Build update query dynamically
        update_fields = []
        params = {'exam_id': exam_id}

        if 'exam_title' in data:
            update_fields.append("exam_title = :exam_title")
            params['exam_title'] = data['exam_title']

        if 'exam_description' in data:
            update_fields.append("exam_description = :exam_description")
            params['exam_description'] = data['exam_description']

        if 'subject' in data:
            update_fields.append("subject = :subject")
            params['subject'] = data['subject']

        if 'total_marks' in data:
            update_fields.append("total_marks = :total_marks")
            params['total_marks'] = data['total_marks']

        if 'duration_minutes' in data:
            update_fields.append("duration_minutes = :duration_minutes")
            params['duration_minutes'] = data['duration_minutes']

        if 'scheduled_date' in data:
            update_fields.append("scheduled_date = :scheduled_date")
            params['scheduled_date'] = datetime.fromisoformat(data['scheduled_date'].replace('Z', '+00:00'))

        if 'end_date' in data:
            update_fields.append("end_date = :end_date")
            params['end_date'] = datetime.fromisoformat(data['end_date'].replace('Z', '+00:00'))

        if 'instructions' in data:
            update_fields.append("instructions = :instructions")
            params['instructions'] = data['instructions']

        if update_fields:
            query = f"UPDATE exams SET {', '.join(update_fields)} WHERE exam_id = :exam_id"
            cursor.execute(query, params)
            conn.commit()

        print("Exam updated successfully")
        print('-' * 60)

        return jsonify({
            'status': 'success',
            'message': 'Exam updated successfully'
        }), 200

    except cx_Oracle.Error as error:
        conn.rollback()
        print(f"DB error: {error}")
        return jsonify({'status': 'error', 'message': str(error)}), 500
    finally:
        cursor.close()
        conn.close()


# 8. Get Teacher Statistics
# Get active exam sessions for teacher monitoring
@app.route('/api/teacher/exam/<int:exam_id>/sessions', methods=['GET'])
@token_required
def get_exam_sessions(current_user, exam_id):
    print('-' * 60)
    print(f"Fetching sessions for exam: {exam_id}")
    print('-' * 60)

    conn = get_db_connection()
    if not conn:
        return jsonify({'status': 'error', 'message': 'DB connection failed'}), 500

    try:
        cursor = conn.cursor()

        cursor.execute("""
            SELECT 
                es.session_id,
                es.student_id,
                u.full_name as student_name,
                s.roll_number,
                es.start_time,
                es.status,
                es.actual_duration_minutes,
                (SELECT COUNT(*) FROM proctoring_logs pl 
                 WHERE pl.session_id = es.session_id) as total_alerts,
                (SELECT COUNT(*) FROM proctoring_logs pl 
                 WHERE pl.session_id = es.session_id 
                 AND pl.severity = 'HIGH') as high_severity_alerts,
                (SELECT COUNT(*) FROM proctoring_logs pl 
                 WHERE pl.session_id = es.session_id 
                 AND pl.severity = 'MEDIUM') as medium_severity_alerts
            FROM exam_sessions es
            JOIN students s ON es.student_id = s.student_id
            JOIN users u ON s.user_id = u.user_id
            WHERE es.exam_id = :exam_id
            ORDER BY es.start_time DESC
        """, exam_id=exam_id)

        sessions = []
        for row in cursor.fetchall():
            sessions.append({
                'session_id': row[0],
                'student_id': row[1],
                'student_name': row[2],
                'roll_number': row[3],
                'start_time': row[4].isoformat() if row[4] else None,
                'status': row[5],
                'duration_minutes': row[6],
                'total_alerts': row[7],
                'high_severity_alerts': row[8],
                'medium_severity_alerts': row[9]
            })

        print(f"Found {len(sessions)} sessions")
        print('-' * 60)

        return jsonify({
            'status': 'success',
            'sessions': sessions
        }), 200

    except cx_Oracle.Error as error:
        print(f"DB error: {error}")
        return jsonify({'status': 'error', 'message': str(error)}), 500
    finally:
        cursor.close()
        conn.close()


# Get proctoring logs for a specific session
@app.route('/api/teacher/session/<int:session_id>/proctoring', methods=['GET'])
@token_required
def get_session_proctoring_logs(current_user, session_id):
    print('-' * 60)
    print(f"Fetching proctoring logs for session: {session_id}")
    print('-' * 60)

    conn = get_db_connection()
    if not conn:
        return jsonify({'status': 'error', 'message': 'DB connection failed'}), 500

    try:
        cursor = conn.cursor()

        # Verify teacher owns this exam
        cursor.execute("""
            SELECT COUNT(*) FROM exam_sessions es
            JOIN exams e ON es.exam_id = e.exam_id
            WHERE es.session_id = :session_id
            AND e.teacher_id = :teacher_id
        """, session_id=session_id, teacher_id=current_user.get('role_id'))

        if cursor.fetchone()[0] == 0:
            return jsonify({'status': 'error', 'message': 'Unauthorized access'}), 403

        # Get proctoring logs
        cursor.execute("""
            SELECT 
                log_id,
                event_type,
                event_description,
                severity,
                detected_at,
                is_reviewed
            FROM proctoring_logs
            WHERE session_id = :session_id
            ORDER BY detected_at DESC
        """, session_id=session_id)

        logs = []
        for row in cursor.fetchall():
            logs.append({
                'log_id': row[0],
                'event_type': row[1],
                'event_description': row[2],
                'severity': row[3],
                'detected_at': row[4].isoformat() if row[4] else None,
                'is_reviewed': bool(row[5])
            })

        print(f"Found {len(logs)} proctoring logs")
        print('-' * 60)

        return jsonify({
            'status': 'success',
            'logs': logs
        }), 200

    except cx_Oracle.Error as error:
        print(f"DB error: {error}")
        return jsonify({'status': 'error', 'message': str(error)}), 500
    finally:
        cursor.close()
        conn.close()


# Disqualify student
@app.route('/api/teacher/session/<int:session_id>/disqualify', methods=['POST'])
@token_required
def disqualify_student_session(current_user, session_id):
    print('-' * 60)
    print(f"Disqualifying session: {session_id}")
    print('-' * 60)

    data = request.get_json()
    reason = data.get('reason', 'Disqualified by instructor')

    conn = get_db_connection()
    if not conn:
        return jsonify({'status': 'error', 'message': 'DB connection failed'}), 500

    try:
        cursor = conn.cursor()

        # Verify teacher owns this exam
        cursor.execute("""
            SELECT COUNT(*) FROM exam_sessions es
            JOIN exams e ON es.exam_id = e.exam_id
            WHERE es.session_id = :session_id
            AND e.teacher_id = :teacher_id
        """, session_id=session_id, teacher_id=current_user.get('role_id'))

        if cursor.fetchone()[0] == 0:
            return jsonify({'status': 'error', 'message': 'Unauthorized access'}), 403

        # Output variables
        status = cursor.var(cx_Oracle.STRING)
        message = cursor.var(cx_Oracle.STRING)

        # Call stored procedure
        cursor.callproc('sp_disqualify_student', [
            session_id,
            reason,
            status,
            message
        ])

        conn.commit()

        final_status = status.getvalue()
        final_message = message.getvalue()

        print(f"Status: {final_status}")
        print(f"Message: {final_message}")
        print('-' * 60)

        if final_status == 'SUCCESS':
            return jsonify({
                'status': 'success',
                'message': final_message
            }), 200
        else:
            return jsonify({
                'status': 'error',
                'message': final_message
            }), 400

    except cx_Oracle.Error as error:
        conn.rollback()
        print(f"DB error: {error}")
        return jsonify({'status': 'error', 'message': str(error)}), 500
    finally:
        cursor.close()
        conn.close()


# Mark proctoring alert as reviewed
@app.route('/api/teacher/proctoring/<int:log_id>/review', methods=['POST'])
@token_required
def review_proctoring_log(current_user, log_id):
    print('-' * 60)
    print(f"Reviewing proctoring log: {log_id}")
    print('-' * 60)

    data = request.get_json()
    action_taken = data.get('action_taken', 'Reviewed by instructor')

    conn = get_db_connection()
    if not conn:
        return jsonify({'status': 'error', 'message': 'DB connection failed'}), 500

    try:
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE proctoring_logs
            SET is_reviewed = 1,
                reviewer_comments = :action_taken
            WHERE log_id = :log_id
        """, log_id=log_id, action_taken=action_taken)

        conn.commit()

        print("Proctoring log reviewed")
        print('-' * 60)

        return jsonify({
            'status': 'success',
            'message': 'Log reviewed successfully'
        }), 200

    except cx_Oracle.Error as error:
        conn.rollback()
        print(f"DB error: {error}")
        return jsonify({'status': 'error', 'message': str(error)}), 500
    finally:
        cursor.close()
        conn.close()


# Get live proctoring stats for an exam
@app.route('/api/teacher/exam/<int:exam_id>/proctoring-stats', methods=['GET'])
@token_required
def get_exam_proctoring_stats(current_user, exam_id):
    print('-' * 60)
    print(f"Fetching proctoring stats for exam: {exam_id}")
    print('-' * 60)

    conn = get_db_connection()
    if not conn:
        return jsonify({'status': 'error', 'message': 'DB connection failed'}), 500

    try:
        cursor = conn.cursor()

        cursor.execute("""
            SELECT 
                COUNT(DISTINCT es.session_id) as total_sessions,
                COUNT(DISTINCT CASE WHEN es.status = 'IN_PROGRESS' THEN es.session_id END) as active_sessions,
                COUNT(DISTINCT CASE WHEN es.status = 'COMPLETED' THEN es.session_id END) as completed_sessions,
                COUNT(DISTINCT pl.log_id) as total_alerts,
                COUNT(DISTINCT CASE WHEN pl.severity = 'HIGH' THEN pl.log_id END) as high_alerts,
                COUNT(DISTINCT CASE WHEN pl.severity = 'MEDIUM' THEN pl.log_id END) as medium_alerts,
                COUNT(DISTINCT CASE WHEN pl.severity = 'LOW' THEN pl.log_id END) as low_alerts
            FROM exam_sessions es
            LEFT JOIN proctoring_logs pl ON es.session_id = pl.session_id
            WHERE es.exam_id = :exam_id
        """, exam_id=exam_id)

        row = cursor.fetchone()

        stats = {
            'total_sessions': row[0] or 0,
            'active_sessions': row[1] or 0,
            'completed_sessions': row[2] or 0,
            'total_alerts': row[3] or 0,
            'high_alerts': row[4] or 0,
            'medium_alerts': row[5] or 0,
            'low_alerts': row[6] or 0
        }

        print(f"Stats: {stats}")
        print('-' * 60)

        return jsonify({
            'status': 'success',
            'stats': stats
        }), 200

    except cx_Oracle.Error as error:
        print(f"DB error: {error}")
        return jsonify({'status': 'error', 'message': str(error)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/teacher/stats', methods=['GET'])
@token_required
def get_teacher_stats(current_user):
    teacher_id = current_user.get('role_id')

    conn = get_db_connection()
    if not conn:
        return jsonify({'status': 'error', 'message': 'DB connection failed'}), 500

    try:
        cursor = conn.cursor()

        cursor.execute("""
            SELECT 
                COUNT(*) as total_exams,
                COUNT(CASE WHEN is_published = 1 THEN 1 END) as published_exams,
                COUNT(CASE WHEN CURRENT_TIMESTAMP BETWEEN scheduled_date AND end_date THEN 1 END) as active_exams,
                (SELECT COUNT(*) FROM exam_sessions es 
                 JOIN exams e ON es.exam_id = e.exam_id 
                 WHERE e.teacher_id = :teacher_id AND es.status = 'COMPLETED') as completed_sessions
            FROM exams
            WHERE teacher_id = :teacher_id
        """, teacher_id=teacher_id)

        row = cursor.fetchone()

        stats = {
            'total_exams': row[0] or 0,
            'published_exams': row[1] or 0,
            'active_exams': row[2] or 0,

            'completed_sessions': row[3] or 0
        }

        return jsonify({
            'status': 'success',
            'stats': stats
        }), 200

    except cx_Oracle.Error as error:
        print(f"DB error: {error}")
        return jsonify({'status': 'error', 'message': str(error)}), 500
    finally:
        cursor.close()
        conn.close()

# Get session details
@app.route('/api/student/session/<int:session_id>', methods=['GET'])
@token_required
def get_session_details(current_user, session_id):
    print('-' * 60)
    print(f"Fetching session details: {session_id}")
    print('-' * 60)

    conn = get_db_connection()
    if not conn:
        return jsonify({'status': 'error', 'message': 'DB connection failed'}), 500

    try:
        cursor = conn.cursor()

        cursor.execute("""
            SELECT 
                es.session_id,
                es.exam_id,
                es.student_id,
                es.start_time,
                es.status,
                e.duration_minutes
            FROM exam_sessions es
            JOIN exams e ON es.exam_id = e.exam_id
            WHERE es.session_id = :session_id
        """, session_id=session_id)

        row = cursor.fetchone()

        if not row:
            return jsonify({'status': 'error', 'message': 'Session not found'}), 404

        session_data = {
            'session_id': row[0],
            'exam_id': row[1],
            'student_id': row[2],
            'start_time': row[3].isoformat() if row[3] else None,
            'status': row[4],
            'duration_minutes': row[5]
        }

        print(f"Session found: {session_data}")
        print('-' * 60)

        return jsonify({
            'status': 'success',
            'session': session_data
        }), 200

    except cx_Oracle.Error as error:
        print(f"DB error: {error}")
        return jsonify({'status': 'error', 'message': str(error)}), 500
    finally:
        cursor.close()
        conn.close()


# Save answer endpoint (simplified name)
@app.route('/api/student/answer/save', methods=['POST'])
@token_required
def save_answer_simplified(current_user):
    """Alternative endpoint name for saving answers"""
    print('-' * 60)
    print("Saving answer (simplified endpoint)")
    print('-' * 60)

    data = request.get_json()

    # Validate required fields
    if not data.get('session_id'):
        return jsonify({'status': 'error', 'message': 'Session ID is required'}), 400

    if not data.get('question_id'):
        return jsonify({'status': 'error', 'message': 'Question ID is required'}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({'status': 'error', 'message': 'DB connection failed'}), 500

    try:
        cursor = conn.cursor()

        # Output variables
        status = cursor.var(cx_Oracle.STRING)
        message = cursor.var(cx_Oracle.STRING)

        # Call stored procedure
        cursor.callproc('sp_submit_answer', [
            data['session_id'],
            data['question_id'],
            data.get('answer_text'),
            data.get('selected_option_id'),
            data.get('is_marked_for_review', 0),
            status,
            message
        ])

        conn.commit()

        final_status = status.getvalue()
        final_message = message.getvalue()

        print(f"Status: {final_status}")
        print(f"Message: {final_message}")
        print('-' * 60)

        if final_status == 'SUCCESS':
            return jsonify({
                'status': 'success',
                'message': final_message
            }), 200
        else:
            return jsonify({
                'status': 'error',
                'message': final_message
            }), 400

    except cx_Oracle.Error as error:
        conn.rollback()
        print(f"DB error: {error}")
        return jsonify({'status': 'error', 'message': str(error)}), 500
    finally:
        cursor.close()
        conn.close()


# Proctoring log endpoint (alternative name)
@app.route('/api/student/proctoring/log', methods=['POST'])
@token_required
def log_proctoring_simplified(current_user):
    """Alternative endpoint name for proctoring logs"""
    print('-' * 60)
    print("Logging proctoring event (simplified endpoint)")
    print('-' * 60)

    data = request.get_json()

    # Validate required fields
    if not data.get('session_id'):
        return jsonify({'status': 'error', 'message': 'Session ID is required'}), 400

    if not data.get('event_type'):
        return jsonify({'status': 'error', 'message': 'Event type is required'}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({'status': 'error', 'message': 'DB connection failed'}), 500

    try:
        cursor = conn.cursor()

        # Output variables
        status = cursor.var(cx_Oracle.STRING)
        message = cursor.var(cx_Oracle.STRING)

        # Call stored procedure
        cursor.callproc('sp_log_proctoring_event', [
            data['session_id'],
            data['event_type'],
            data.get('event_description', ''),
            data.get('severity', 'LOW'),
            data.get('evidence_url'),
            status,
            message
        ])

        conn.commit()

        final_status = status.getvalue()
        final_message = message.getvalue()

        print(f"Event Type: {data['event_type']}")
        print(f"Severity: {data.get('severity', 'LOW')}")
        print(f"Status: {final_status}")
        print('-' * 60)

        if final_status == 'SUCCESS':
            return jsonify({
                'status': 'success',
                'message': final_message
            }), 200
        else:
            return jsonify({
                'status': 'error',
                'message': final_message
            }), 400

    except cx_Oracle.Error as error:
        conn.rollback()
        print(f"DB error: {error}")
        return jsonify({'status': 'error', 'message': str(error)}), 500
    finally:
        cursor.close()
        conn.close()


# Submit exam endpoint
@app.route('/api/student/exam/submit', methods=['POST'])
@token_required
def submit_exam_endpoint(current_user):
    print('-' * 60)
    print("Submitting exam")
    print('-' * 60)

    data = request.get_json()
    session_id = data.get('session_id')
    force_submit = data.get('force_submit', 0)

    if not session_id:
        return jsonify({'status': 'error', 'message': 'Session ID is required'}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({'status': 'error', 'message': 'DB connection failed'}), 500

    try:
        cursor = conn.cursor()

        # Output variables
        status = cursor.var(cx_Oracle.STRING)
        message = cursor.var(cx_Oracle.STRING)

        # Call stored procedure
        cursor.callproc('sp_end_exam_session', [
            session_id,
            force_submit,
            status,
            message
        ])

        conn.commit()

        final_status = status.getvalue()
        final_message = message.getvalue()

        print(f"Status: {final_status}")
        print(f"Message: {final_message}")
        print('-' * 60)

        if final_status == 'SUCCESS':
            return jsonify({
                'status': 'success',
                'message': final_message
            }), 200
        else:
            return jsonify({
                'status': 'error',
                'message': final_message
            }), 400

    except cx_Oracle.Error as error:
        conn.rollback()
        print(f"DB error: {error}")
        return jsonify({'status': 'error', 'message': str(error)}), 500
    finally:
        cursor.close()
        conn.close()


# Get exam result
@app.route('/api/student/exam/result/<int:session_id>', methods=['GET'])
@token_required
def get_exam_result(current_user, session_id):
    print('-' * 60)
    print(f"Fetching exam result for session: {session_id}")
    print('-' * 60)

    student_id = current_user.get('role_id')

    conn = get_db_connection()
    if not conn:
        return jsonify({'status': 'error', 'message': 'DB connection failed'}), 500

    try:
        cursor = conn.cursor()

        cursor.execute("""
            SELECT 
                er.result_id,
                er.exam_id,
                e.exam_title,
                e.subject,
                er.total_marks_obtained,
                e.total_marks,
                er.percentage,
                er.grade,
                er.status,
                er.rank_in_exam,
                es.actual_duration_minutes,
                er.evaluated_at,
                (SELECT COUNT(*) FROM proctoring_logs pl 
                 WHERE pl.session_id = :session_id) as total_flags,
                (SELECT COUNT(*) FROM proctoring_logs pl 
                 WHERE pl.session_id = :session_id AND pl.severity = 'HIGH') as high_severity_flags,
                (SELECT COUNT(*) FROM proctoring_logs pl 
                 WHERE pl.session_id = :session_id AND pl.severity = 'MEDIUM') as medium_severity_flags
            FROM exam_results er
            JOIN exam_sessions es ON er.session_id = es.session_id
            JOIN exams e ON er.exam_id = e.exam_id
            WHERE er.session_id = :session_id
            AND er.student_id = :student_id
        """, session_id=session_id, student_id=student_id)

        row = cursor.fetchone()

        if not row:
            return jsonify({'status': 'error', 'message': 'Result not found'}), 404

        result = {
            'result_id': row[0],
            'exam_id': row[1],
            'exam_title': row[2],
            'subject': row[3],
            'marks_obtained': row[4],
            'total_marks': row[5],
            'percentage': float(row[6]) if row[6] else 0,
            'grade': row[7],
            'status': row[8],
            'rank': row[9],
            'duration_minutes': row[10],
            'evaluated_at': row[11].isoformat() if row[11] else None,
            'proctoring_summary': {
                'total_flags': row[12],
                'high_severity': row[13],
                'medium_severity': row[14]
            }
        }

        # Get proctoring events
        cursor.execute("""
            SELECT 
                event_type,
                event_description,
                severity,
                detected_at
            FROM proctoring_logs
            WHERE session_id = :session_id
            ORDER BY detected_at DESC
        """, session_id=session_id)

        events = []
        for event_row in cursor.fetchall():
            events.append({
                'event_type': event_row[0],
                'description': event_row[1],
                'severity': event_row[2],
                'time': event_row[3].isoformat() if event_row[3] else None
            })

        result['proctoring_events'] = events

        print(f"Result found: {result['grade']} - {result['percentage']}%")
        print('-' * 60)

        return jsonify({
            'status': 'success',
            'result': result
        }), 200

    except cx_Oracle.Error as error:
        print(f"DB error: {error}")
        return jsonify({'status': 'error', 'message': str(error)}), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/api/student/exam/<int:exam_id>/start', methods=['POST'])
@token_required
def start_exam_session(current_user, exam_id):
    print('-' * 60)
    print(f"Starting exam session for exam: {exam_id}")
    print('-' * 60)

    data = request.get_json()
    student_id = current_user.get('role_id')

    # Get device info from request
    ip_address = request.remote_addr
    browser_info = data.get('browser_info', request.headers.get('User-Agent', 'Unknown'))
    device_info = data.get('device_info', 'Unknown')

    print(f"Student ID: {student_id}")
    print(f"IP Address: {ip_address}")
    print(f"Browser: {browser_info}")
    print(f"Device: {device_info}")

    conn = get_db_connection()
    if not conn:
        return jsonify({'status': 'error', 'message': 'DB connection failed'}), 500

    try:
        cursor = conn.cursor()

        # Output variables
        session_id = cursor.var(cx_Oracle.NUMBER)
        status = cursor.var(cx_Oracle.STRING)
        message = cursor.var(cx_Oracle.STRING)

        # Call stored procedure
        cursor.callproc('sp_start_exam_session', [
            exam_id,
            student_id,
            ip_address,
            browser_info,
            device_info,
            session_id,
            status,
            message
        ])

        conn.commit()

        final_status = status.getvalue()
        final_message = message.getvalue()
        final_session_id = session_id.getvalue()

        print(f"Status: {final_status}")
        print(f"Message: {final_message}")
        print(f"Session ID: {final_session_id}")
        print('-' * 60)

        if final_status == 'SUCCESS':
            return jsonify({
                'status': 'success',
                'message': final_message,
                'session_id': final_session_id
            }), 201
        else:
            return jsonify({
                'status': 'error',
                'message': final_message
            }), 400

    except cx_Oracle.Error as error:
        conn.rollback()
        print(f"DB error: {error}")
        return jsonify({'status': 'error', 'message': str(error)}), 500
    finally:
        cursor.close()
        conn.close()


# Get exam questions endpoint
@app.route('/api/student/exam/<int:exam_id>/questions', methods=['GET'])
@token_required
def get_exam_questions(current_user, exam_id):
    print('-' * 60)
    print(f"Fetching questions for exam: {exam_id}")
    print('-' * 60)

    conn = get_db_connection()
    if not conn:
        return jsonify({'status': 'error', 'message': 'DB connection failed'}), 500

    try:
        cursor = conn.cursor()

        # Get questions
        cursor.execute("""
            SELECT 
                q.question_id,
                q.question_text,
                q.question_type,
                q.marks,
                q.question_order,
                q.image_url
            FROM questions q
            WHERE q.exam_id = :exam_id
            ORDER BY q.question_order
        """, exam_id=exam_id)

        questions = []
        for row in cursor.fetchall():
            # Convert CLOB to string
            question_text = row[1].read() if hasattr(row[1], 'read') else str(row[1])

            question = {
                'question_id': row[0],
                'question_text': question_text,
                'question_type': row[2],
                'marks': row[3],
                'question_order': row[4],
                'image_url': row[5],
                'options': []
            }

            # Get MCQ options if applicable
            if row[2] in ['MCQ', 'TRUE_FALSE']:
                print(f"  Getting options for question {row[0]}...")

                cursor.execute("""
                    SELECT option_id, option_text, option_order
                    FROM mcq_options
                    WHERE question_id = :question_id
                    ORDER BY option_order
                """, question_id=row[0])

                option_rows = cursor.fetchall()
                print(f"  Found {len(option_rows)} options")

                for opt_row in option_rows:
                    # Handle option_order - it's a CHAR(1) in database
                    opt_order = opt_row[2]
                    if isinstance(opt_order, str):
                        opt_order = opt_order.strip()
                    else:
                        opt_order = str(opt_order)

                    option = {
                        'option_id': opt_row[0],
                        'option_text': opt_row[1],
                        'option_order': opt_order
                    }
                    question['options'].append(option)
                    print(f"    Option {opt_order}: {opt_row[1][:50]}...")

            questions.append(question)

        print(f"✅ Returning {len(questions)} questions")
        print('-' * 60)

        return jsonify({
            'status': 'success',
            'questions': questions
        }), 200

    except cx_Oracle.Error as error:
        print(f"❌ DB error: {error}")
        import traceback
        print(traceback.format_exc())
        return jsonify({'status': 'error', 'message': str(error)}), 500
    finally:
        cursor.close()
        conn.close()

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)