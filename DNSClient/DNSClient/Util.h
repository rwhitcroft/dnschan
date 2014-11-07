#ifndef __UTIL_H__
#define __UTIL_H__

#include <algorithm>
#include <string>
#include <vector>
using namespace std;

class Util
{
public:
	static string to_string(const wstring&);
	static wstring to_wstring(const string&);
	static string replace_char(const string&, char, char);
	static string order_chunks(vector<string>);

private:
	Util() { }
	~Util() { }
};

#endif
