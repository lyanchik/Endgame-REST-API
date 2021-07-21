import sqlite3
import json
import logging

def init_history(data):
	logging.basicConfig(filename="log.txt",
						filemode="a",
						format="SQL message | "
							+ f"%(asctime)s,%(msecs)d "
							+ f"%(levelname)s: %(message)s",
							datefmt='%H:%M:%S',
							level=logging.DEBUG)	
	db = None
	try:
		db = sqlite3.connect('hist')
		logging.info("DataBase is connected")
		c = db.cursor()
		c.execute("""CREATE TABLE IF NOT EXISTS requests(
					Method TEXT,
					URL TEXT,
					Params BLOB,
					Headers BLOB,
					Body BLOB,
					Auth BLOB,
					Status INTEGER,
					Response BLOB,
					Favourite TEXT DEFAULT 'False');""")
		logging.info("Table is created")
		col = ', '.join(data.keys())
		ph = ', '.join('?' * len(data))
		query = 'INSERT INTO requests ({}) VALUES ({})'.format(col, ph)
		values = [json.dumps(x) if type(x) == dict else x for x in data.values()]
		c.execute(query, values)
		db.commit()
		if c.rowcount:
			logging.info("Data was inserted")
	except Exception as e:
		logging.error(e)
	finally:
		if db:
			db.close()
	