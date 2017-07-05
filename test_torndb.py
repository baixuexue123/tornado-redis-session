#!/usr/bin/env python3
import torndb


db = torndb.Connection(host='localhost', database='blog', user='blog', password='blog', connect_timeout=5)

print(db.get("SELECT * FROM authors WHERE email = %s", "123"))

print(db.query("SELECT * FROM entries ORDER BY published DESC LIMIT 5"))
