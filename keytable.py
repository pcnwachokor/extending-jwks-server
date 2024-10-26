import sqlite3

#Connect to the SQLite database (creates it if it doesn't exist)
db_name = "totally_not_my_privateKeys.db"
conn = sqlite3.connect(db_name)

#Create a cursor to execute SQL queries
cursor = conn.cursor()

#Create table
cursor.execute('''
    CREATE TABLE IF NOT EXISTS keys (
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    )
''')

#Commit the changes and close the connection
conn.commit()
conn.close()

print(f"Database '{db_name}' and 'keys' table created successfully.")
