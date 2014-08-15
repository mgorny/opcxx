#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif

#include <opcua/struct.hxx>
#include <opcua/tcp.hxx>
#include <opcua/types.hxx>
#include <opcua/util.hxx>

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

int main()
{
	// set libevent up
	event_base* ev = event_base_new();
	assert(ev);

	opc_ua::tcp::TransportStream f(ev);
	opc_ua::tcp::MessageStream ms1(f);
	opc_ua::tcp::MessageStream ms2(f);

	f.connect_hostname("127.0.0.1", 6001, endpoint.c_str());

	// main loop
	event_base_loop(ev, 0);

	// cleanup
	event_base_free(ev);
}
