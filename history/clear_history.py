import sqlite3
import logging

def clear_history(id=None):
	logging.basicConfig(filename="log.txt",
						filemode="a",
						format="SQL message | "
							+ f"%(asctime)s %(msecs)d "
							+ f"%(levelname)s: %(message)s",
							datefmt='%H:%M:%S',
							level=logging.DEBUG)
	try:
		db = sqlite3.connect('hist')
		logging.info("DataBase is connected")
		c = db.cursor()
		tables = c.execute("""SELECT name
						FROM sqlite_master WHERE type='table'
  						AND name='requests';""").fetchall()
		if tables == []:
			logging.warning("Table doesn't exist")
		else:
			if id:
				c.execute("DELETE FROM requests WHERE"
						+ f" rowid LIKE {str(id)};")
			else:
				c.execute("DROP TABLE requests;")
			db.commit()
			if c.rowcount:
				if id:
					logging.info("{id} was deleted")
				else:
					logging.info("table is clear")
	except Exception as e:
		logging.error(e)
	finally:
		if db:
			db.close()
