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



class TestVar : public opc_ua::Variable
{
	virtual opc_ua::NodeId node_id()
	{
		return {"sampleBuilding", 2};
	}

	virtual opc_ua::NodeClass node_class()
	{
		return opc_ua::NodeClass::VARIABLE;
	}

	virtual opc_ua::QualifiedName browse_name()
	{
		return {"sampleBuilding", 2};
	}

	virtual opc_ua::LocalizedText display_name(opc_ua::Session& s)
	{
		return {"en", "sample building"};
	}

	virtual opc_ua::UInt32 write_mask(opc_ua::Session& s)
	{
		return 0;
	}

	virtual opc_ua::UInt32 user_write_mask(opc_ua::Session& s)
	{
		return 0;
	}

	virtual opc_ua::Variant value(opc_ua::Session& s)
	{
		return static_cast<opc_ua::Int32>(1000);
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

int main()
{
	// set libevent up
	event_base* ev = event_base_new();
	assert(ev);

	TestVar v;

	opc_ua::AddressSpace as;
	opc_ua::tcp::Server s(ev, as);

	as.add_node({&v, null_deleter<TestVar>()});

	mt.connect();

	// main loop
	event_base_loop(ev, 0);

	// cleanup
	event_base_free(ev);
	mt.disconnect();
}
