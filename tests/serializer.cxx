/* OPC UA protocol implementation
 * (c) 2014 Michał Górny
 * Licensed under the terms of the 2-clause BSD license
 */

#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif

#include <opcua/common/types.hxx>
#include <opcua/common/util.hxx>
#include <opcua/tcp/types.hxx>

#include <cstring>

template <class T>
void test_serialization(const T& val1)
{
	opc_ua::TemporarySerializationContext ctx;
	opc_ua::tcp::BinarySerializer s;
	T val2;

	s.serialize(ctx, val1);
	s.unserialize(ctx, val2);

	if (val1 != val2)
		throw std::runtime_error("Serialization + unserialization returns different result");
}

int main()
{
	// Integral types
	test_serialization<opc_ua::Byte>(0);
	test_serialization<opc_ua::Byte>(15);
	test_serialization<opc_ua::Byte>(255);
	test_serialization<opc_ua::UInt16>(0x0060);
	test_serialization<opc_ua::UInt16>(0x2345);
	test_serialization<opc_ua::UInt32>(0x11335577);
	test_serialization<opc_ua::UInt32>(0xffffffff);
	test_serialization<opc_ua::Int32>(-0x10000000);
	test_serialization<opc_ua::Int32>(0x12343210);
	test_serialization<opc_ua::Int64>(-0x0044008800cc00ff);
	test_serialization<opc_ua::Int64>(0x44008800cc00ff00);

	// Floating-point types
	test_serialization<opc_ua::Double>(0.5551);
	test_serialization<opc_ua::Double>(-3.33);

	// String type
	test_serialization<opc_ua::String>("");
	test_serialization<opc_ua::String>("foobarbaz");

	// NodeID
	test_serialization<opc_ua::NodeId>({25, 2});
	test_serialization<opc_ua::NodeId>({0xaa00, 2});
	test_serialization<opc_ua::NodeId>({0x33bbccdd, 0x1100});
	test_serialization<opc_ua::NodeId>({"foobarbaz", 2});

	opc_ua::GUID g;
	memcpy(g.guid.data(), "ABCDEFGHIJKLMNOP", sizeof(g.guid));
	test_serialization<opc_ua::NodeId>({g, 2});

	return 0;
}
