#ifndef __PACKET_H__
#define __PACKET_H__

#include <string>
using std::string;

class Packet
{
public:
	Packet(unsigned char, unsigned char, unsigned char, const string&);

	// variables
	unsigned char client_id;
	unsigned char packet_id;
	unsigned char opcode;
	string data;
	string domain;

	// methods
	string flatten();
};

#endif
