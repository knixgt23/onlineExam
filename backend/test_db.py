import cx_Oracle

config={
    'user':'C##exam_admin',
    'password':'exam_password_123',
    'dsn':'localhost:1521/XE'
}

try:
    connection=cx_Oracle.connect(**config)
    print("DB connection Success")

    cursor=connection.cursor()

    cursor.execute("SELECT COUNT(*) FROM user_tables")
    table_count=cursor.fetchone()[0]
    print(f"Tables found: {table_count}")

    cursor.execute("""
    SELECT COUNT(*) FROM user_objects WHERE object_name='SP_REGISTER_USER' AND object_type='PROCEDURE'""")
    proc_exists=cursor.fetchone()[0]

    if proc_exists:
        print("SP_REGISTER_USER procedure exists")
    else:
        print("SP_REGISTER_USER procedure not found")

    cursor.close()
    connection.close()
    print("Everything looks good!")

except cx_Oracle.Error as error:
    print(f"Error: {error}")