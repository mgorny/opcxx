#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif

#include <opcua/common/struct.hxx>
#include <opcua/tcp/server.hxx>
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

opc_ua::tcp::BinarySerializer srl;

std::unordered_map<opc_ua::GUID, int> tadam;

int main()
{
	// set libevent up
	event_base* ev = event_base_new();
	assert(ev);

	opc_ua::tcp::Server s(ev);

	tadam.emplace(opc_ua::GUID(), 1);

	// main loop
	event_base_loop(ev, 0);

	// cleanup
	event_base_free(ev);
}
