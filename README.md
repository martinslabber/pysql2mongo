pysql2mongo
===========

Python functions to convert SQL query to mongo query
At present this is a utility to print how simple SQL select statements will look like as mongo queries.
Best place to see what it can do is the test.py file.

Requirements
============

* pyparsing
* pymongo

Usage Examples
==============

> `./sql2mongo.py -q -n "SELECT name, phone_no FROM users WHERE name = 'bob the builder' AND hourly_rate <= 1000"`


	The SQL query:  select name, phone_no from users where name = 'bob the builder' and hourly_rate <= 1000

	is this mongo query:  db.users.find({$and:[{name:'bob the builder'}, {hourly_rate:{$lte:1000}}]}, {_id:0, name:1, phone_no:1})


TODO
====
There is so much.

* Skip and Limit
* Orderby
* Run queries against a live DB
* Display results in table format (or json when -j is given)
* Restructure to form a better reusable library

