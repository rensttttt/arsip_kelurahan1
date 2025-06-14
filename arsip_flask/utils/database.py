# arsip_app/utils/database.py
from mysql.connector import connect, Error

def get_database_config(config=None):
    if config is None:
        from arsip_flask.config import Config
        config = Config()
    return {
        "host": config.DB_HOST,
        "user": config.DB_USER,
        "password": config.DB_PASSWORD,
        "database": config.DB_NAME,
        "raise_on_warnings": True,
        "charset": "utf8mb4",
    }

def get_db_connection():
    try:
        conn = connect(**get_database_config())
        if conn.is_connected():
            return conn
    except Error as e:
        print(f"DB Error: {e}")
    return None
