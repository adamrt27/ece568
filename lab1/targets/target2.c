#include <stdio.h>
#include <string.h>

#define PROGRAMNAME_LEN		10

// ECE568
// Lab 1: target2.c

// The source materials you are provided in this lab are for your personal
// use only, as part of ECE568. Please do not post this file publicly
// (including on sites like GitHub, CourseHero, etc.).

// Please send any bug reports to Courtney Gibson <courtney.gibson@utoronto.ca>

unsigned long long stackLocation = 0x056801000;


void
printProgramName(const char * buffer)
{
	// Print the program name

	char	programName[PROGRAMNAME_LEN];

	strncpy(programName, buffer, PROGRAMNAME_LEN);
	printf("Running %s\n", programName);
}


int
main(const int argc, const char * argv[])
{
	printProgramName(argv[0]);
	return(0);
}
