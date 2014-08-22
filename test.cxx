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

void on_started(std::unique_ptr<opc_ua::Response> msg, void* data)
{
	opc_ua::tcp::SessionStream* self = static_cast<opc_ua::tcp::SessionStream*>(data);

	opc_ua::ReadRequest rvr;
	rvr.max_age = 0;
	rvr.timestamps_to_return = opc_ua::TimestampsToReturn::SERVER;
	rvr.nodes_to_read.emplace_back();
	rvr.nodes_to_read[0].node_id = opc_ua::NodeId("sampleBuilding", 2);
	rvr.nodes_to_read[0].attribute_id = 3;
	for (int i = 0; i < 200; ++i)
		rvr.nodes_to_read.push_back(rvr.nodes_to_read[0]);
	self->write_message(rvr, [] (std::unique_ptr<opc_ua::Response> msg, void* data) {}, data);

	//ns=2;'sampleBuilding'
}

int main()
{
	// set libevent up
	event_base* ev = event_base_new();
	assert(ev);

	opc_ua::tcp::TransportStream f(ev);
	opc_ua::tcp::MessageStream ms1(f);
	opc_ua::tcp::SessionStream ss("foo");

	ss.attach(ms1, endpoint, on_started, &ss);
	f.connect_hostname("127.0.0.1", 6001, endpoint);

	// main loop
	event_base_loop(ev, 0);

	// cleanup
	event_base_free(ev);
}
