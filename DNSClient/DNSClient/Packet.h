#ifndef __PACKET_H__
#define __PACKET_H__

#include <string>
using std::string;

class Packet
{
public:
	Packet(unsigned int, unsigned char, const string&);

	// variables
	unsigned int client_id;
	unsigned char opcode;
	string data;
	string domain;

	// methods
	string flatten();
};

#endif
