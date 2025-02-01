#include <stdio.h>
#include <string.h>

#include "tmalloc.h"

// ECE568
// Lab 1: target4.c

// The source materials you are provided in this lab are for your personal
// use only, as part of ECE568. Please do not post this file publicly
// (including on sites like GitHub, CourseHero, etc.).

// Please send any bug reports to Courtney Gibson <courtney.gibson@utoronto.ca>

unsigned long long stackLocation = 0x056801000;


int
main(const int argc, const char * argv[])
{
	// IMPORTANT NOTE: this function will be called "lab_main"
	// (not "main") if you are analyzing this code in gdb

	printf("Running target4...\n");

	char *	p = tmalloc(72);
	char *	q = tmalloc(120);

	tfree(p);
	tfree(q);

	p = tmalloc(192);

	strncpy(p, argv[0], 192);

	tfree(q);

	return(0);
}
