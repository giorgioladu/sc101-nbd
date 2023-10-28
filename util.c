/*
 *  Copyright (C) 2007  Iain Wade <iwade@optusnet.com.au>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "util.h"

/* Convert a double to a struct timeval */
struct timeval dbl2tv(double d)
{
    struct timeval tv;

    tv.tv_sec = (long) d;
    tv.tv_usec = (long) ((d - (long) d) * 1000000.0);

    return tv;
}

void *copy(void *buf, int len)
{
    void *ret;
    if (!(ret = malloc(len)))
    return NULL;
    memcpy(ret, buf, len);
    return ret;
}

void dump_hex(uint8_t *buf, int len)
{
    fprintf(stdout, "DUMP:\n");

    for (int i = 0; i < len; i += 32)
    {
    for (int n = 0; n < 32; n++)
        if (i + n < len)
        fprintf(stdout, "%02hhx", buf[i+n]);
        else
        fprintf(stdout, "  ");

    fprintf(stdout, "\t");

    for (int n = 0; n < 32 && i + n < len; n++)
        fprintf(stdout, "%c", isprint(buf[i+n]) ? buf[i+n] : '.');

    fprintf(stdout, "\n");
    }
}

uint64_t get_uint48(uint8_t *buf)
{
    off_t ret = 0;
    for (int i = 0; i < 6; i++)
    ret = (ret << 8) | buf[i];
    return ret;
}

uint64_t ntohll(uint64_t a)
{
    uint32_t lo = a & 0xffffffff;
    uint32_t hi = a >> 32U;
    lo = ntohl(lo);
    hi = ntohl(hi);
    return ((uint64_t) lo) << 32U | hi;
}

char *gpt_utf16le2ascii(char *utf16le_str, size_t sz) {

  iconv_t cd;
  int     rc;
  char   *p;
  size_t  sz_in, sz_out;
  char   *str_out;
  size_t  conv_sz;

  // ASCII string is shorter than UTF16
  sz_out = sz;
  str_out = (char *)malloc(sz_out);
  if (!str_out) {
    fprintf(stderr, "malloc(%zu): %s (%d)\n", sz, strerror(errno), errno);
    return 0;
  }

  cd = iconv_open("ASCII", "UTF-16LE");
  if (cd == (iconv_t)-1) {
    fprintf(stderr, "iconv_open(): %s (%d)\n", strerror(errno), errno);
    free(str_out);
    return 0;
  }

  sz_in = sz;
  //str_in = utf16le_str;
  p = str_out;
  conv_sz = iconv(cd, &utf16le_str, &sz_in, &p, &sz_out);
  if (conv_sz == (size_t)-1) {
    fprintf(stderr, "iconv(): %s (%d)\n", strerror(errno), errno);
    free(str_out);
    iconv_close(cd);
    return 0;
  }

  str_out[sz-sz_out] = '\0';

  rc = iconv_close(cd);
  if (rc == -1) {
    fprintf(stderr, "iconv_open(): %s (%d)\n", strerror(errno), errno);
    free(str_out);
    return 0;
  }

  return str_out;
}


/*
//function to convert string to byte array
unsigned char *string2ByteArray(char* input)
{
    int loop=0;
   // unsigned char output[sizeof(input)];
   unsigned char *output = malloc(sizeof(input));

    while (input[loop] != '\0') {
        output[loop] = input[loop];
         loop++;
    }

    return (output);
}*/

#define htonll ntohll
