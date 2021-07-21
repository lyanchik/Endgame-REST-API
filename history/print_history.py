import sqlite3
import json
import logging

def print_history(query="Method, URL, Params, Body, Status",
					sort="rowid", num=10, full=False, cond=None):
	logging.basicConfig(filename="log.txt",
						filemode="a",
						format="SQL message | "
							+ f"%(asctime)s,%(msecs)d "
							+ f"%(levelname)s: %(message)s",
							datefmt='%H:%M:%S',
							level=logging.DEBUG)
	db = None
	result = list()
	like = ""
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
			if cond and type(cond) == dict:
				like = "WHERE"
				last_key = list(cond.keys())[-1]
				for key, val in cond.items():
					like += f" {key} LIKE {str(val)}"
					if key != last_key:
						like += " AND "
			if full == False:
				c.execute(f"SELECT * FROM (SELECT rowid as ID, {query} FROM "
							+ f"requests {like} ORDER BY {sort} DESC LIMIT "
							+ f"{num})Var1 ORDER BY ID ASC;")
			else:
				c.execute(f"SELECT rowid as ID, {query} FROM "
							+ f"requests {like} ORDER BY {sort}")
			logging.info(f"{query} is proceed")
			for row in c.fetchall():
				item = dict()
				for i, val in enumerate(row):
					if ((c.description[i][0] == "Params"  and val != None)
						or (c.description[i][0] == "Body" and val != None)
						or (c.description[i][0] == "Response" and val != None)
						or (c.description[i][0] == "Headers" and val != None)
						or (c.description[i][0] == "Auth" and val != None)):
						item[c.description[i][0]] = json.loads(val)
					else:
						item[c.description[i][0]] = val
				result.append(item)	
			return result
	except Exception as e:
		logging.error(e)
	finally:
		if db:
			db.close()