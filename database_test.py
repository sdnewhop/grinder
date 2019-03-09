#!/usr/bin/python3

from grinder.dbhandling import GrinderDatabase

db = GrinderDatabase()
db.load_last_results()
# db.create_db()
# db.initiate_scan()
# json_dict = {
#     'test1': 1,
#     'testNone': None,
#     'test0': 0,
#     'testdict': {'1': 1}
# }
# db.add_scan_data('myvendor', 'myproduct', 'myquery', 'myscript', 'myconfidence', json_dict)
db.close()