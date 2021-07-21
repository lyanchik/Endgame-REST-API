import sqlite3
import logging

def update_fav(id):
	logging.basicConfig(filename="log.txt",
						filemode="a",
						format="SQL message | "
							+ f"%(asctime)s %(msecs)d "
							+ f"%(levelname)s: %(message)s",
							datefmt='%H:%M:%S',
							level=logging.DEBUG)	
	db = None

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
			fav = c.execute("SELECT Favourite FROM requests "
							+ f"WHERE rowid LIKE {str(id)}").fetchone()
			if fav[0] == 'False':
				c.execute("UPDATE requests SET Favourite = 'True' "
					+ f"WHERE rowid LIKE {str(id)}")
			else:
			 	c.execute("UPDATE requests SET Favourite = 'False' "
					+ f"WHERE rowid LIKE {str(id)}")
			db.commit()
			if c.rowcount:
					logging.info(f"{id} 'Favourite' was updated")
	except Exception as e:
		logging.error(e)
	finally:
		if db:
			db.close()