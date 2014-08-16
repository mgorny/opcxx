#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif

#include <opcua/common/struct.hxx>
#include <opcua/tcp/streams.hxx>
#include <opcua/common/types.hxx>
#include <opcua/common/util.hxx>

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/event.h>

#include <sys/socket.h>

#include <cassert>
#include <iomanip>
#include <iostream>
#include <stdexcept>

std::string endpoint("opc.tcp://127.0.0.1:6001/sampleuaserver");
opc_ua::tcp::BinarySerializer srl;

class MyStream : public opc_ua::tcp::MessageStream
{
protected:
	void on_connected()
	{
//		close();
	}

	void on_message(std::unique_ptr<opc_ua::Message>, opc_ua::UInt32 req_id)
	{
	}

public:
	MyStream(opc_ua::tcp::TransportStream& ts)
		: MessageStream(ts)
	{
	}
};

class MyStream2 : public opc_ua::tcp::MessageStream
{
protected:
	void on_connected()
	{
	}

	void on_message(std::unique_ptr<opc_ua::Message> body, opc_ua::UInt32 req_id)
	{
	}


public:
	MyStream2(opc_ua::tcp::TransportStream& ts)
		: MessageStream(ts)
	{
	}
};

int main()
{
	// set libevent up
	event_base* ev = event_base_new();
	assert(ev);

	opc_ua::tcp::TransportStream f(ev);
	MyStream ms1(f);
	MyStream2 ms2(f);

	f.connect_hostname("127.0.0.1", 6001, endpoint.c_str());

	// main loop
	event_base_loop(ev, 0);

	// cleanup
	event_base_free(ev);
}
