#include <stdio.h>
#include <string.h>

#define PROGRAMNAME_LEN		10
#define SECRETBUFFER_LEN	25
#define SECRET_STRING		"***ECE568 SECRET STRING!"

// ECE568
// Lab 1: target1.c

// The source materials you are provided in this lab are for your personal
// use only, as part of ECE568. Please do not post this file publicly
// (including on sites like GitHub, CourseHero, etc.).

// Please send any bug reports to Courtney Gibson <courtney.gibson@utoronto.ca>


int
main(const int argc, const char * argv[])
{
	char	secretBuffer[SECRETBUFFER_LEN];
	char	programName[PROGRAMNAME_LEN];

	// Copy in the secret string
	strncpy(secretBuffer, SECRET_STRING, SECRETBUFFER_LEN);

	// Print the program name

	strncpy(programName, argv[0], PROGRAMNAME_LEN);
	printf("Running %s\n", programName);

	return(0);
}
