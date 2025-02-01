#!/usr/bin/python3

# ECE568
# Lab 2: createValues.py

# The source materials you are provided in this lab are for your personal
# use only, as part of ECE568. Please do not post this file publicly
# (including on sites like GitHub, CourseHero, etc.).

# Please send any bug reports to Courtney Gibson <courtney.gibson@utoronto.ca>


import	json
import	random
import	string


filename	= 'values.json'
alphanumeric	= string.ascii_letters + string.digits
numEntries	= random.randrange(500,1000)
entries		= []


# Generate between 500 and 1000 random strings

for e in range(numEntries):

	generateNewEntry = True

	while generateNewEntry:

		# Generate a string of between 10 and 20 alphanumeric characters

		randomString = ''.join(random.choice(alphanumeric)
					for i in range(random.randrange(10,20)))

		# While it's highly-unlikely, check that this isn't a duplicate

		if ( randomString not in entries ):

			# Not a duplicate: add it to the array

			entries += [ randomString ]
			generateNewEntry = False

# Write the entires out to the file, in JSON format

print("Writing %d random entries to %s" % (numEntries, filename))

with open(filename, 'w') as outputFile:
	json.dump(entries, outputFile)

