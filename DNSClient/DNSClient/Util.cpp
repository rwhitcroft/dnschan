#include "Util.h"

string Util::to_string(const wstring& s)
{
	return string(s.begin(), s.end());
}

wstring Util::to_wstring(const string& s)
{
	return wstring(s.begin(), s.end());
}

string Util::replace_char(const string& s, char from, char to)
{
	string ret;
	for(auto it = s.begin(); it != s.end(); ++it) {
		if(*it == from)
			ret += to;
		else
			ret += *it;
	}

	return ret;
}

string Util::order_chunks(vector<string> chunks)
{
	string ret;

	// sort the array
	sort(chunks.begin(), chunks.end());

	// with the sorted array, erase the leading index and comma from each element
	for(auto it = chunks.begin(); it != chunks.end(); ++it) {
		*it->erase(it->begin(), it->begin() + 1);
		ret += *it;
	}

	return ret;
}
