#include <sstream>
#include "Base64.h"
#include "Packet.h"
using namespace std;

Packet::Packet(unsigned int i, unsigned char c, const string& s)
{
	client_id = i;
	opcode = c;
	data = s;
	domain = ".sub.domain.tld"; // leading dot required
}

string Packet::flatten()
{
	stringstream ss;
	ss << client_id << opcode << data;

	string ret = ss.str();
	while(ret.size() % 3 != 0)
		ret += " ";

	return string(en64(ret) + domain);
}
