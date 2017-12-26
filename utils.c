#include <stdarg.h>
#include <stdio.h>

char *append_buff(char *buf, const char *format, ...) {
	va_list args;
	va_start(args, format);
	
	int n = vsprintf(buf, format, args);
	
	va_end(args);
	return (buf + n);
}
