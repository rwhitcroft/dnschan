#ifndef __BASE64_H__
#define __BASE64_H__

#include <string>
using std::string;

string base64_encode(unsigned char const*, unsigned int);
string base64_decode(const string&);
string de64(const string&);
string en64(const string&);

#endif
