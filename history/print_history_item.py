import sqlite3
import json
import logging

def print_history_item(id):
	logging.basicConfig(filename="log.txt",
						filemode="a",
						format="SQL message | "
							+ f"%(asctime)s,%(msecs)d "
							+ f"%(levelname)s: %(message)s",
							datefmt='%H:%M:%S',
							level=logging.DEBUG)
	db = None
	result = dict()
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
			c.execute(f"SELECT * FROM requests WHERE rowid LIKE {str(id)}")
			fetch = c.fetchall()
			if len(fetch) > 0:
				logging.info(f"Query on {id} was created")
				for i in range(len(fetch[0])):
					if ((c.description[i][0] == "Params"  and fetch[0][i] != None)
						or (c.description[i][0] == "Body" and fetch[0][i] != None)
						or (c.description[i][0] == "Response" and fetch[0][i] != None)
						or (c.description[i][0] == "Headers" and fetch[0][i] != None)
						or (c.description[i][0] == "Auth" and fetch[0][i] != None)):
						result[c.description[i][0]] = json.loads(fetch[0][i])
					else:
						result[c.description[i][0]] = fetch[0][i]
				return result
			else:
				logging.error(f"No such {id} in table")
	except Exception as e:
		logging.error(f"print history {e}")
	finally:
		if db:
			db.close()