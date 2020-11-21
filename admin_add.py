import sqlite3
from sqlite3 import Error
from passlib.context import CryptContext

username = "admin"
password = "admin"
permission = 0
database = "db.sqlite"
password_hash = CryptContext(schemes=["bcrypt"], deprecated="auto").hash(password)
user = (username, password_hash, permission)


conn = sqlite3.connect(database)

with conn:
	cur = conn.cursor()
	sql = ''' INSERT INTO users(username, password, permission)
			VALUES(?,?,?) '''
	cur.execute(sql, user)
