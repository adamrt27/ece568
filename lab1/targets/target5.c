#include <stdio.h>
#include <stdint.h>
#include <string.h>

// ECE568
// Lab 1: target5.c

// The source materials you are provided in this lab are for your personal
// use only, as part of ECE568. Please do not post this file publicly
// (including on sites like GitHub, CourseHero, etc.).

// Please send any bug reports to Courtney Gibson <courtney.gibson@utoronto.ca>

unsigned long long stackLocation = 0x056801000;

#define	BUFFER_LEN		256

char *	buffer;
char *	args;
char *	cpoint;

int
main (const int argc, const char * argv[] )
{
	// IMPORTANT NOTE: this function will be called "lab_main"
	// (not "main") if you are analyzing this code in gdb

	printf("Running target5...\n");

	// To make things easier for this lab, we will copy
	// the parameters passed in via execve into a local
	// 64-bit-aligned buffer on the stack, before the
	// call to snprintf

	uint64_t	alignedBuffer[BUFFER_LEN / sizeof(uint64_t)];
	uint64_t	alignedArgs[BUFFER_LEN / sizeof(uint64_t)];

	buffer = (char *)alignedBuffer;
	args = (char *)alignedArgs;

	// Copy all of the argv[] parameters into args

	cpoint = args;
	for ( uint16_t p = 0; p < argc; p++ ) {

		size_t len = strlen(argv[p]);
		for ( uint16_t i = 0; i < len && cpoint < &args[BUFFER_LEN-1]; i++ )
			*(cpoint++) = argv[p][i];
		*(cpoint++) = '\0';
	}

	// Now call snprintf...

	snprintf(buffer, BUFFER_LEN, args);

	return (0);
}
