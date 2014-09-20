#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif

#include <opcua/common/object.hxx>
#include <opcua/common/struct.hxx>
#include <opcua/tcp/server.hxx>
#include <opcua/common/types.hxx>
#include <opcua/common/util.hxx>

#include <mt101/mt101.hxx>

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/event.h>

#include <sys/socket.h>

#include <cassert>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <stdexcept>

opc_ua::tcp::BinarySerializer srl;

mt101::MT101 mt;
struct timespec last_fetched = {0, 0};

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

void refetch_if_old(time_t max_age) // [ms]
{
	struct timespec curr_time;
	if (clock_gettime(CLOCK_MONOTONIC, &curr_time))
		throw std::runtime_error("clock_gettime() failed");

	time_t sec_diff = curr_time.tv_sec - last_fetched.tv_sec;
	int_least16_t ms_diff = (curr_time.tv_nsec - last_fetched.tv_nsec) / 1E6;
	if (ms_diff < 0)
	{
		ms_diff += 1000;
		--sec_diff;
	}

	time_t max_age_sec = max_age / 1000;
	int_least16_t max_age_ms = max_age % 1000;

	if (sec_diff > max_age_sec || (sec_diff == max_age_sec && ms_diff > max_age_ms))
	{
		mt.fetch();
		last_fetched = curr_time;
	}
}

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
	size_t my_off;

public:
	MT101BinaryInput(const std::string& node_id, const std::string& desc, size_t off)
		: MT101Variable(node_id, desc), my_off(off)
	{
	}

	virtual opc_ua::Variant value(opc_ua::Session& s, opc_ua::Double max_age)
	{
		refetch_if_old(max_age);

		return mt.get_binary_input_state(my_off);
	}

	virtual opc_ua::StatusCode value(opc_ua::Session& s, const opc_ua::Variant& new_value)
	{
		return 0;
	}
};

std::unique_ptr<event, event_deleter> flush_output_event;

class MT101BinaryOutput : public MT101Variable
{
	size_t my_off;

public:
	MT101BinaryOutput(const std::string& node_id, const std::string& desc, size_t off)
		: MT101Variable(node_id, desc), my_off(off)
	{
	}

	virtual opc_ua::Variant value(opc_ua::Session& s, opc_ua::Double max_age)
	{
		refetch_if_old(max_age);

		return mt.get_binary_output_state(my_off);
	}

	virtual opc_ua::StatusCode value(opc_ua::Session& s, const opc_ua::Variant& new_value)
	{
		if (new_value.variant_type != opc_ua::VariantType::BOOLEAN)
			throw std::runtime_error("Wrong data type for binary output");
		mt.set_binary_output_state(my_off, new_value.as_boolean);

		struct timeval zero_time = {0, 0};
		event_add(flush_output_event.get(), &zero_time);

		return 0;
	}
};

class MT101AnalogInput : public MT101Variable
{
	size_t my_off;

public:
	MT101AnalogInput(const std::string& node_id, const std::string& desc, size_t off)
		: MT101Variable(node_id, desc), my_off(off)
	{
	}

	virtual opc_ua::Variant value(opc_ua::Session& s, opc_ua::Double max_age)
	{
		refetch_if_old(max_age);

		return mt.get_analog_input_value(my_off);
	}

	virtual opc_ua::StatusCode value(opc_ua::Session& s, const opc_ua::Variant& new_value)
	{
		return 0;
	}
};

static void flush_handler(int fd, short what, void* data)
{
	mt.flush();
}

int main()
{
	// set libevent up
	event_base* ev = event_base_new();
	assert(ev);

	opc_ua::AddressSpace as;
	opc_ua::tcp::Server s(ev, as);

	as.add_node(std::make_shared<MT101BinaryInput>("I1", "binary input 1", mt101::consts::I1));
	as.add_node(std::make_shared<MT101BinaryInput>("I2", "binary input 2", mt101::consts::I2));
	as.add_node(std::make_shared<MT101BinaryInput>("I3", "binary input 3", mt101::consts::I3));
	as.add_node(std::make_shared<MT101BinaryInput>("I4", "binary input 4", mt101::consts::I4));
	as.add_node(std::make_shared<MT101BinaryInput>("I5", "binary input 5", mt101::consts::I5));
	as.add_node(std::make_shared<MT101BinaryInput>("I6", "binary input 6", mt101::consts::I6));
	as.add_node(std::make_shared<MT101BinaryInput>("I7", "binary input 7", mt101::consts::I7));
	as.add_node(std::make_shared<MT101BinaryInput>("I8", "binary input 8", mt101::consts::I8));
	as.add_node(std::make_shared<MT101BinaryOutput>("Q1", "binary output 1", mt101::consts::Q1));
	as.add_node(std::make_shared<MT101BinaryOutput>("Q2", "binary output 2", mt101::consts::Q2));
	as.add_node(std::make_shared<MT101BinaryOutput>("Q3", "binary output 3", mt101::consts::Q3));
	as.add_node(std::make_shared<MT101BinaryOutput>("Q4", "binary output 4", mt101::consts::Q4));
	as.add_node(std::make_shared<MT101BinaryOutput>("Q5", "binary output 5", mt101::consts::Q5));
	as.add_node(std::make_shared<MT101BinaryOutput>("Q6", "binary output 6", mt101::consts::Q6));
	as.add_node(std::make_shared<MT101BinaryOutput>("Q7", "binary output 7", mt101::consts::Q7));
	as.add_node(std::make_shared<MT101BinaryOutput>("Q8", "binary output 8", mt101::consts::Q8));
	as.add_node(std::make_shared<MT101BinaryOutput>("Q7", "binary output 7", mt101::consts::Q7));
	as.add_node(std::make_shared<MT101BinaryOutput>("Q8", "binary output 8", mt101::consts::Q8));
	as.add_node(std::make_shared<MT101AnalogInput>("AN1", "analog input 1", mt101::consts::AN1));
	as.add_node(std::make_shared<MT101AnalogInput>("AN2", "analog input 2", mt101::consts::AN2));

	mt.connect();

	// output flusher
	flush_output_event.reset(evtimer_new(ev, flush_handler, nullptr));

	// main loop
	event_base_loop(ev, 0);

	// cleanup
	event_base_free(ev);
	mt.disconnect();
}
