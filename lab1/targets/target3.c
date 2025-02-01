#include <stdio.h>
#include <string.h>

#define PROGRAMNAME_LEN		128

// ECE568
// Lab 1: target3.c

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

	char	programName[PROGRAMNAME_LEN];

	printf("Running target3...\n");

	strcpy(programName, argv[0]);

	return(0);
}

// 
