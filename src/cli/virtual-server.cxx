/* Simple OPC UA server emulating virtual MT-101
 * (c) 2014 Michał Górny
 * Licensed under the terms of the 2-clause BSD license
 */

#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif

#include <opcua/common/object.hxx>
#include <opcua/common/struct.hxx>
#include <opcua/tcp/server.hxx>
#include <opcua/common/types.hxx>
#include <opcua/common/util.hxx>

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/event.h>

#include <sys/socket.h>

#include <ncurses.h>

#include <array>
#include <bitset>
#include <cassert>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>

opc_ua::tcp::BinarySerializer srl;

template <class T>
struct null_deleter
{
	void operator()(T*& ptr)
	{
	}
};

struct event_deleter
{
	void operator()(event* p)
	{
		event_free(p);
	}
};

std::bitset<8> input_bits;
std::bitset<8> output_bits;
std::array<uint16_t, 2> analog_inputs;

class NCurses
{
	WINDOW* mainwin;

	std::bitset<8> prev_input_bits;
	std::bitset<8> prev_output_bits;
	std::array<uint16_t, 2> prev_analog_inputs;

	std::unique_ptr<event, event_deleter> kb_event;
	std::unique_ptr<event, event_deleter> refresh_event;

public:
	void print_values()
	{
		bool any_change
			= (input_bits != prev_input_bits)
			|| (output_bits != prev_output_bits)
			|| (analog_inputs != prev_analog_inputs);

		for (int i = 0; i < 8; ++i)
		{
			if (input_bits[i] != prev_input_bits[i])
				attron(A_BOLD);
			else
				attroff(A_BOLD);

			color_set(input_bits[i] ? 2 : 1, nullptr);
			mvaddstr(3, 2 + i*2, input_bits[i] ? "+" : "-");
		}

		for (int i = 0; i < 8; ++i)
		{
			if (output_bits[i] != prev_output_bits[i])
				attron(A_BOLD);
			else
				attroff(A_BOLD);

			color_set(output_bits[i] ? 2 : 1, nullptr);
			mvaddstr(3, 20 + i*2, output_bits[i] ? "+" : "-");
		}

		for (int i = 0; i < 2; ++i)
		{
			if (analog_inputs[i] != prev_analog_inputs[i])
			{
				attron(A_BOLD);
				color_set(analog_inputs[i] > prev_analog_inputs[i] ? 2 : 1, nullptr);
			}
			else
			{
				attroff(A_BOLD);
				color_set(3, nullptr);
			}

			std::string sv = std::to_string(analog_inputs[i]);

			mvaddstr(3, 38 + 8*i, "     ");
			mvaddstr(3, 38 + 8*i + 5 - sv.size(), sv.c_str());
		}

		refresh();

		prev_input_bits = input_bits;
		prev_output_bits = output_bits;
		prev_analog_inputs = analog_inputs;

		if (any_change)
		{
			// queue another refresh to dim the lights
			struct timeval some_time = {3, 0};
			event_add(refresh_event.get(), &some_time);
		}
	}

	static void kb_handler(evutil_socket_t fd, short st, void* data)
	{
		NCurses* nc = static_cast<NCurses*>(data);
		bool refr = false;

		while (1)
		{
			int c = getch();
			if (c == -1)
				break;

			bool inner_refr = true;

			switch (c)
			{
				case '1': input_bits[0].flip(); break;
				case '2': input_bits[1].flip(); break;
				case '3': input_bits[2].flip(); break;
				case '4': input_bits[3].flip(); break;
				case '5': input_bits[4].flip(); break;
				case '6': input_bits[5].flip(); break;
				case '7': input_bits[6].flip(); break;
				case '8': input_bits[7].flip(); break;

				case 'q': case 'Q': output_bits[0].flip(); break;
				case 'w': case 'W': output_bits[1].flip(); break;
				case 'e': case 'E': output_bits[2].flip(); break;
				case 'r': case 'R': output_bits[3].flip(); break;
				case 't': case 'T': output_bits[4].flip(); break;
				case 'y': case 'Y': output_bits[5].flip(); break;
				case 'u': case 'U': output_bits[6].flip(); break;
				case 'i': case 'I': output_bits[7].flip(); break;

				case 'A': analog_inputs[0] += 30; break;
				case 'a': analog_inputs[0] += 1; break;
				case 'Z': analog_inputs[0] -= 30; break;
				case 'z': analog_inputs[0] -= 1; break;
				case 'S': analog_inputs[1] += 30; break;
				case 's': analog_inputs[1] += 1; break;
				case 'X': analog_inputs[1] -= 30; break;
				case 'x': analog_inputs[1] -= 1; break;
				default:
					inner_refr = false;
			}

			refr |= inner_refr;
		}

		if (refr)
			nc->print_values();
	}

	static void refresh_values(evutil_socket_t fd, short st, void* data)
	{
		NCurses* nc = static_cast<NCurses*>(data);
		nc->print_values();
	}

	void queue_refresh()
	{
		struct timeval zero_time = {0, 0};
		event_add(refresh_event.get(), &zero_time);
	}

	NCurses(event_base* ev)
		: prev_input_bits(input_bits),
		prev_output_bits(output_bits),
		prev_analog_inputs(analog_inputs)
	{
		mainwin = initscr();
		if (!mainwin)
			throw std::runtime_error("Unable to init ncurses");

		// disable input buffering (read char-by-char)
		cbreak();
		// disable input echo
		noecho();
		// make input reads non-blocking
		nodelay(mainwin, TRUE);
		// support keypad
		keypad(mainwin, TRUE);

		// enable colors
		start_color();
		use_default_colors();
		init_pair(1, COLOR_RED, -1);
		init_pair(2, COLOR_GREEN, -1);
		init_pair(3, COLOR_YELLOW, -1);

		mvaddstr(0, 0, "~~~~~~~~~~~~~~~~ Virtual MT-101 server ~~~~~~~~~~~~~~");
		mvaddstr(1, 0, "|  Digital inputs | Digital outputs | Analog inputs |");
		mvaddstr(2, 0, "| 1 2 3 4 5 6 7 8 | Q W E R T Y U I | z 1 a | x 2 s |");
		mvaddstr(3, 0, "|                 |                 |       |       |");
		mvaddstr(4, 0, "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");

		print_values();

		kb_event.reset(event_new(ev, 0, EV_READ | EV_PERSIST, kb_handler, this));
		event_add(kb_event.get(), nullptr);
		refresh_event.reset(evtimer_new(ev, refresh_values, this));
	}

	~NCurses()
	{
		delwin(mainwin);
		endwin();
		refresh();
	}
};

class MT101Variable : public opc_ua::Variable
{
	std::string my_node_id, my_desc;

public:
	MT101Variable(const std::string& node_id, const std::string& desc)
		: my_node_id(node_id), my_desc(desc)
	{
	}

	virtual opc_ua::NodeId node_id()
	{
		return {my_node_id, 1};
	}

	virtual opc_ua::NodeClass node_class()
	{
		return opc_ua::NodeClass::VARIABLE;
	}

	virtual opc_ua::QualifiedName browse_name()
	{
		return {my_node_id, 1};
	}

	virtual opc_ua::LocalizedText display_name(opc_ua::Session& s, opc_ua::Double max_age)
	{
		return {"en", my_desc};
	}

	virtual opc_ua::UInt32 write_mask(opc_ua::Session& s, opc_ua::Double max_age)
	{
		return 0;
	}

	virtual opc_ua::UInt32 user_write_mask(opc_ua::Session& s, opc_ua::Double max_age)
	{
		return 0;
	}

	virtual opc_ua::NodeId data_type(opc_ua::Session& s, opc_ua::Double max_age)
	{
		return {};
	}

	virtual opc_ua::Int32 value_rank(opc_ua::Session& s, opc_ua::Double max_age)
	{
		return -1;
	}

	virtual opc_ua::Array<opc_ua::UInt32> array_dimensions(opc_ua::Session& s, opc_ua::Double max_age)
	{
		return {};
	}

	virtual opc_ua::Byte access_level(opc_ua::Session& s, opc_ua::Double max_age)
	{
		return 1;
	}

	virtual opc_ua::Byte user_access_level(opc_ua::Session& s, opc_ua::Double max_age)
	{
		return 1;
	}

	virtual opc_ua::Boolean historizing(opc_ua::Session& s, opc_ua::Double max_age)
	{
		return false;
	}
};

class MT101BinaryInput : public MT101Variable
{
	std::bitset<8>::reference r;

public:
	MT101BinaryInput(const std::string& node_id, const std::string& desc, std::bitset<8>::reference bit_ref)
		: MT101Variable(node_id, desc), r(bit_ref)
	{
	}

	virtual opc_ua::Variant value(opc_ua::Session& s, opc_ua::Double max_age)
	{
		return static_cast<opc_ua::Boolean>(r);
	}

	virtual opc_ua::StatusCode value(opc_ua::Session& s, const opc_ua::Variant& new_value)
	{
		return 0;
	}
};

std::unique_ptr<event, event_deleter> flush_output_event;

class NCurses; // opaque

class MT101BinaryOutput : public MT101Variable
{
	std::bitset<8>::reference r;
	NCurses& nc;

public:
	MT101BinaryOutput(const std::string& node_id, const std::string& desc, std::bitset<8>::reference bit_ref, NCurses& my_nc)
		: MT101Variable(node_id, desc), r(bit_ref), nc(my_nc)
	{
	}

	virtual opc_ua::Variant value(opc_ua::Session& s, opc_ua::Double max_age)
	{
		return static_cast<opc_ua::Boolean>(r);
	}

	virtual opc_ua::StatusCode value(opc_ua::Session& s, const opc_ua::Variant& new_value)
	{
		if (new_value.variant_type != opc_ua::VariantType::BOOLEAN)
			throw std::runtime_error("Attempting to set binary output to non-boolean");
		r = new_value.as_boolean;
		nc.queue_refresh();
		return 0;
	}
};

class MT101AnalogInput : public MT101Variable
{
	uint16_t& val;

public:
	MT101AnalogInput(const std::string& node_id, const std::string& desc, uint16_t& val_ref)
		: MT101Variable(node_id, desc), val(val_ref)
	{
	}

	virtual opc_ua::Variant value(opc_ua::Session& s, opc_ua::Double max_age)
	{
		return val;
	}

	virtual opc_ua::StatusCode value(opc_ua::Session& s, const opc_ua::Variant& new_value)
	{
		return 0;
	}
};

int main()
{
	// set libevent up
	event_base* ev = event_base_new();
	assert(ev);

	opc_ua::AddressSpace as;
	opc_ua::tcp::Server s(ev, as);

	NCurses nc(ev);

	as.add_node(std::make_shared<MT101BinaryInput>("I1", "binary input 1", input_bits[0]));
	as.add_node(std::make_shared<MT101BinaryInput>("I2", "binary input 2", input_bits[1]));
	as.add_node(std::make_shared<MT101BinaryInput>("I3", "binary input 3", input_bits[2]));
	as.add_node(std::make_shared<MT101BinaryInput>("I4", "binary input 4", input_bits[3]));
	as.add_node(std::make_shared<MT101BinaryInput>("I5", "binary input 5", input_bits[4]));
	as.add_node(std::make_shared<MT101BinaryInput>("I6", "binary input 6", input_bits[5]));
	as.add_node(std::make_shared<MT101BinaryInput>("I7", "binary input 7", input_bits[6]));
	as.add_node(std::make_shared<MT101BinaryInput>("I8", "binary input 8", input_bits[7]));
	as.add_node(std::make_shared<MT101BinaryOutput>("Q1", "binary output 1", output_bits[0], nc));
	as.add_node(std::make_shared<MT101BinaryOutput>("Q2", "binary output 2", output_bits[1], nc));
	as.add_node(std::make_shared<MT101BinaryOutput>("Q3", "binary output 3", output_bits[2], nc));
	as.add_node(std::make_shared<MT101BinaryOutput>("Q4", "binary output 4", output_bits[3], nc));
	as.add_node(std::make_shared<MT101BinaryOutput>("Q5", "binary output 5", output_bits[4], nc));
	as.add_node(std::make_shared<MT101BinaryOutput>("Q6", "binary output 6", output_bits[5], nc));
	as.add_node(std::make_shared<MT101BinaryOutput>("Q7", "binary output 7", output_bits[6], nc));
	as.add_node(std::make_shared<MT101BinaryOutput>("Q8", "binary output 8", output_bits[7], nc));
	as.add_node(std::make_shared<MT101AnalogInput>("AN1", "analog input 1", analog_inputs[0]));
	as.add_node(std::make_shared<MT101AnalogInput>("AN2", "analog input 2", analog_inputs[1]));

	// main loop
	event_base_loop(ev, 0);

	// cleanup
	event_base_free(ev);
}
