#ifndef KPM_LIBC_H
#define KPM_LIBC_H

/* Minimal libc subset shared by all KPM C code */

void* kpm_memcpy(void* dest, const void* src, unsigned long n);
void* kpm_memset(void* s, int c, unsigned long n);
int   kpm_memcmp(const void* a, const void* b, unsigned long n);
unsigned long kpm_strlen(const char* s);
int   kpm_strcmp(const char* a, const char* b);
int   kpm_strncmp(const char* a, const char* b, unsigned long n);
char* kpm_strcpy(char* dest, const char* src);
char* kpm_strncpy(char* dest, const char* src, unsigned long n);

/* Debug helpers */
void kpm_cache_flush_range(const void* start, unsigned long size);

#endif /* KPM_LIBC_H */
