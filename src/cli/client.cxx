/* Simple OPC UA-controlled MT101 client
 * (c) 2014 Michał Górny
 * Licensed under the terms of the 2-clause BSD license
 */

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

#include <array>
#include <bitset>
#include <cassert>
#include <iomanip>
#include <iostream>
#include <stdexcept>

std::array<const char*, 8> digital_inputs{{"I1", "I2", "I3", "I4", "I5", "I6", "I7", "I8"}};
std::array<const char*, 8> digital_outputs{{"Q1", "Q2", "Q3", "Q4", "Q5", "Q6", "Q7", "Q8"}};
std::array<const char*, 2> analog_inputs{{"AN1", "AN2"}};

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

static void set_output_bits(opc_ua::tcp::SessionStream& s, std::bitset<8> bits)
{
	opc_ua::WriteRequest wvr;

	for (int i = 0; i < 8; ++i)
	{
		wvr.nodes_to_write.emplace_back();
		wvr.nodes_to_write.back().node_id = opc_ua::NodeId(digital_outputs[i], 1);
		wvr.nodes_to_write.back().attribute_id = static_cast<opc_ua::UInt32>(opc_ua::AttributeId::VALUE);
		wvr.nodes_to_write.back().value.flags = static_cast<opc_ua::Byte>(opc_ua::DataValueFlags::VALUE_SPECIFIED);
		wvr.nodes_to_write.back().value.value = static_cast<opc_ua::Variant>(bits[i]);
	}

	s.write_message(wvr, [] (std::unique_ptr<opc_ua::Response>, void*) {}, nullptr);
}

static int line_counter = 0;
static const char* color_reset = "\e[0m";
static const char* color_red = "\e[31m";
static const char* color_green = "\e[32m";
static const char* color_brown = "\e[33m";
static const char* attr_bold = "\e[1m";

// pattern used to set outputs
static std::bitset<8> xor_pattern = 0b00101110;

static std::bitset<8> input_bits;
static std::bitset<8> output_bits;
static std::array<uint16_t, 2> analog_values;

static void response_handler(std::unique_ptr<opc_ua::Response> msg, void* data)
{
	timer_callback_data* cb_data = static_cast<timer_callback_data*>(data);
	opc_ua::ReadResponse* rsp = dynamic_cast<opc_ua::ReadResponse*>(msg.get());

	int i = 0;

	if (!(line_counter++ % 20))
	{
		std::cerr << "\n"
			"|  Digital inputs | Digital outputs | Analog inputs |      Timestamp      |\n"
			"| 1 2 3 4 5 6 7 8 | 1 2 3 4 5 6 7 8 |   1   |   2   |                     |\n"
			"+-----------------+-----------------+-------+-------+---------------------+\n";
		line_counter = 1;
	}

	std::cout << "| ";
	for (auto v : rsp->results)
	{
		// error
		if (v.flags & static_cast<opc_ua::Byte>(opc_ua::DataValueFlags::STATUS_CODE_SPECIFIED))
			std::cerr << color_brown << "E" << color_reset << std::endl;
		else
		{
			switch (v.value.variant_type)
			{
				case opc_ua::VariantType::BOOLEAN:
					assert(i < 16);

					if ((i < 8 && input_bits[i] != v.value.as_boolean)
							|| (i >= 8 && i < 16 && output_bits[i & 7] != v.value.as_boolean))
						std::cerr << attr_bold;

					std::cerr << (v.value.as_boolean ? color_green : color_red)
						<< v.value.as_boolean << color_reset;
					break;
				case opc_ua::VariantType::UINT16:
					assert(i >= 16);

					if (analog_values[i & 3] != v.value.as_uint16)
					{
						std::cerr << attr_bold
							<< ((analog_values[i & 3] < v.value.as_uint16)
								? color_green : color_red);
					}
					else
						std::cerr << color_brown;

					std::cerr << std::setw(5) << v.value.as_uint16 << color_reset;
					break;
				default:
					std::cerr << static_cast<int>(v.value.variant_type) << std::endl;
					throw std::runtime_error("Incorrect value type");
			}
		}

		if (i < 8)
			input_bits[i] = v.value.as_boolean;
		else if (i < 16)
			output_bits[i & 7] = v.value.as_boolean;
		else
			analog_values[i & 3] = v.value.as_uint16;

		if (i == 7 || i >= 15)
			std::cerr << " | ";
		else
			std::cerr << " ";
		++i;
	}
	struct tm* timestamp = localtime(&rsp->response_header.timestamp.ts.tv_sec);
	char time_buf[20];
	assert(strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", timestamp) != 0);
	std::cerr << time_buf << " |" << std::endl;

	std::bitset<8> new_output_bits = input_bits ^ xor_pattern;
	new_output_bits ^= (analog_values[0] & 0xff0) >> 4;
	new_output_bits ^= (analog_values[1] & 0xff00) >> 8;
	if (new_output_bits != output_bits)
		set_output_bits(cb_data->session_stream, new_output_bits);

	struct timeval timer_delay = {.tv_sec = 2, .tv_usec = 0};
	event_add(cb_data->timer_event.get(), &timer_delay);
}

static void timer_handler(int fd, short what, void* data)
{
	timer_callback_data* cb_data = static_cast<timer_callback_data*>(data);
	opc_ua::tcp::SessionStream& self = cb_data->session_stream;

	opc_ua::ReadRequest rvr;
	rvr.max_age = 1500;
	rvr.timestamps_to_return = opc_ua::TimestampsToReturn::SERVER;

	for (const char* node_name : digital_inputs)
	{
		rvr.nodes_to_read.emplace_back();
		rvr.nodes_to_read.back().node_id = opc_ua::NodeId(node_name, 1);
		rvr.nodes_to_read.back().attribute_id = static_cast<opc_ua::UInt32>(opc_ua::AttributeId::VALUE);
	}
	for (const char* node_name : digital_outputs)
	{
		rvr.nodes_to_read.emplace_back();
		rvr.nodes_to_read.back().node_id = opc_ua::NodeId(node_name, 1);
		rvr.nodes_to_read.back().attribute_id = static_cast<opc_ua::UInt32>(opc_ua::AttributeId::VALUE);
	}
	for (const char* node_name : analog_inputs)
	{
		rvr.nodes_to_read.emplace_back();
		rvr.nodes_to_read.back().node_id = opc_ua::NodeId(node_name, 1);
		rvr.nodes_to_read.back().attribute_id = static_cast<opc_ua::UInt32>(opc_ua::AttributeId::VALUE);
	}

	self.write_message(rvr, response_handler, data);
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
