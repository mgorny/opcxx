#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif

#include <opcua/common/object.hxx>
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

struct event_deleter
{
	void operator()(event* p)
	{
		event_free(p);
	}
};

struct timer_callback_data
{
	event_base* evbase;
	opc_ua::tcp::SessionStream& session_stream;
	std::unique_ptr<event, event_deleter> timer_event;
};

static void timer_handler(int fd, short what, void* data)
{
	timer_callback_data* cb_data = static_cast<timer_callback_data*>(data);
	opc_ua::tcp::SessionStream& self = cb_data->session_stream;

	opc_ua::ReadRequest rvr;
	rvr.max_age = 0;
	rvr.timestamps_to_return = opc_ua::TimestampsToReturn::SERVER;
	rvr.nodes_to_read.emplace_back();
	rvr.nodes_to_read[0].node_id = opc_ua::NodeId("I1", 1);
	rvr.nodes_to_read[0].attribute_id = static_cast<opc_ua::UInt32>(opc_ua::AttributeId::VALUE);
	self.write_message(rvr, [] (std::unique_ptr<opc_ua::Response> msg, void* data)
		{
			timer_callback_data* cb_data = static_cast<timer_callback_data*>(data);

			opc_ua::ReadResponse* rsp = dynamic_cast<opc_ua::ReadResponse*>(msg.get());
			std::cout << "I1: " << rsp->results[0].value.as_boolean << std::endl;

			struct timeval timer_delay = {.tv_sec = 2, .tv_usec = 0};
			event_add(cb_data->timer_event.get(), &timer_delay);
		}, data);

	//ns=2;'sampleBuilding'
}

void on_started(std::unique_ptr<opc_ua::Response> msg, void* data)
{
	timer_callback_data* cb_data = static_cast<timer_callback_data*>(data);
	cb_data->timer_event.reset(evtimer_new(cb_data->evbase, timer_handler, cb_data));

	struct timeval zero_time = {0, 0};
	event_add(cb_data->timer_event.get(), &zero_time);
}

int main()
{
	// set libevent up
	event_base* ev = event_base_new();
	assert(ev);

	opc_ua::tcp::TransportStream f(ev);
	opc_ua::tcp::MessageStream ms1(f);
	opc_ua::tcp::SessionStream ss("foo");

	timer_callback_data cb_data = {
		.evbase = ev,
		.session_stream = ss,
		.timer_event = {},
	};

	ss.attach(ms1, endpoint, on_started, &cb_data);
	f.connect_hostname("127.0.0.1", 6001, endpoint);

	// main loop
	event_base_loop(ev, 0);

	// cleanup
	event_base_free(ev);
}
