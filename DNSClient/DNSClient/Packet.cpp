#include <sstream>
#include "Base64.h"
#include "Packet.h"
using namespace std;

Packet::Packet(unsigned char i, unsigned char p, unsigned char c, const string& s)
{
	client_id = i;
	packet_id = p;
	opcode = c;
	data = s;
	domain = ".sub.domain.tld"; // leading dot required
	//printf("created Packet: %d %d %d %s\n", client_id, packet_id, opcode, s.c_str());
}

string Packet::flatten()
{
	stringstream ss;
	ss << client_id << packet_id << opcode << data;

	string ret = ss.str();
	while(ret.size() % 3 != 0)
		ret += " ";

	return string(en64(ret) + domain);
}
