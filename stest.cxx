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
#include <iomanip>
#include <iostream>
#include <stdexcept>

opc_ua::tcp::BinarySerializer srl;

mt101::MT101 mt;

template <class T>
struct null_deleter
{
	void operator()(T*& ptr)
	{
	}
};

time_t get_mt101_rtc_time(mt101::MT101 mt)
{
	struct tm t;

	t.tm_sec = mt.get_analog_input_value(mt101::consts::RTC_Sec);
	t.tm_min = mt.get_analog_input_value(mt101::consts::RTC_Min);
	t.tm_hour = mt.get_analog_input_value(mt101::consts::RTC_Hour);
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

	virtual opc_ua::LocalizedText display_name(opc_ua::Session& s)
	{
		return {"en", my_desc};
	}

	virtual opc_ua::UInt32 write_mask(opc_ua::Session& s)
	{
		return 0;
	}

	virtual opc_ua::UInt32 user_write_mask(opc_ua::Session& s)
	{
		return 0;
	}

	virtual opc_ua::NodeId data_type(opc_ua::Session& s)
	{
		return {};
	}

	virtual opc_ua::Int32 value_rank(opc_ua::Session& s)
	{
		return -1;
	}

	virtual opc_ua::Array<opc_ua::UInt32> array_dimensions(opc_ua::Session& s)
	{
		return {};
	}

	virtual opc_ua::Byte access_level(opc_ua::Session& s)
	{
		return 1;
	}

	virtual opc_ua::Byte user_access_level(opc_ua::Session& s)
	{
		return 1;
	}

	virtual opc_ua::Boolean historizing(opc_ua::Session& s)
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

	virtual opc_ua::Variant value(opc_ua::Session& s)
	{
		mt.fetch();

		return mt.get_binary_input_state(my_off);
	}
};

class MT101BinaryOutput : public MT101Variable
{
	size_t my_off;

public:
	MT101BinaryOutput(const std::string& node_id, const std::string& desc, size_t off)
		: MT101Variable(node_id, desc), my_off(off)
	{
	}

	virtual opc_ua::Variant value(opc_ua::Session& s)
	{
		mt.fetch();

		return mt.get_binary_output_state(my_off);
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

	virtual opc_ua::Variant value(opc_ua::Session& s)
	{
		mt.fetch();

		return mt.get_analog_input_value(my_off);
	}
};

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

	// main loop
	event_base_loop(ev, 0);

	// cleanup
	event_base_free(ev);
	mt.disconnect();
}
