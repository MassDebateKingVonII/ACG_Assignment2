from mysql.connector import pooling
import os
from dotenv import load_dotenv

load_dotenv()

# Create a connection pool
db_pool = pooling.MySQLConnectionPool(
    pool_name="mypool",
    pool_size=5,                 # number of connections
    pool_reset_session=True,
    host=os.getenv("DB_HOST"),
    user=os.getenv("DB_USER"),
    password=os.getenv("DB_PASS"),
    database=os.getenv("DB_NAME"),
    autocommit = True,
    ssl_disabled= False           # TLS assumed ON
)

def get_db():
    conn = db_pool.get_connection()
    return conn