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

int main()
{
	// set libevent up
	event_base* ev = event_base_new();
	assert(ev);

	opc_ua::AddressSpace as;
	opc_ua::tcp::Server s(ev, as);

	as.add_node(std::make_shared<MT101BinaryInput>("I1", "binary input 1", mt101::consts::I1));

	mt.connect();

	// main loop
	event_base_loop(ev, 0);

	// cleanup
	event_base_free(ev);
	mt.disconnect();
}
