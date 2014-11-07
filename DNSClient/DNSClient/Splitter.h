#ifndef __SPLIT_H__
#define __SPLIT_H__

// split() borrowed from http://stackoverflow.com/questions/236129/splitting-a-string-in-c

#include <string>
#include <sstream>
#include <vector>
using namespace std;

typedef wchar_t WCHAR;

class Splitter
{
public:
	static vector<string> split(const string&, char);

private:
	Splitter();
	~Splitter();
	static vector<string>& split(const string&, char, vector<string>&);
};

#endif
