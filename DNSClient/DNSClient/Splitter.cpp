#include "Splitter.h"

Splitter::Splitter() { }

Splitter::~Splitter() { }

vector<string>& Splitter::split(const string& s, char delim, vector<string>& elems) {
	stringstream ss(s);
	string item;
	while (getline(ss, item, delim)) {
		elems.push_back(item);
	}
	return elems;
}

vector<string> Splitter::split(const string& s, char delim) {
	vector<string> elems;
	split(s, delim, elems);
	return elems;
}
