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

#include <cstdint>

template <class T>
void test_unserialize(const std::vector<uint8_t> ser_val, const T& val1)
{
	opc_ua::MemorySerializationBuffer buf;
	opc_ua::tcp::BinarySerializer s;
	T val2;

	// move data into a buffer
	buf.write(ser_val.data(), ser_val.size());

	// unserialize the value
	s.unserialize(buf, val2);

	if (val1 != val2)
		throw std::logic_error("Unserialization returned different value");
}

template <class T>
void test_serialize(const T& val1, const std::vector<uint8_t> ser_exp)
{
	opc_ua::MemorySerializationBuffer buf;
	opc_ua::tcp::BinarySerializer s;
	std::vector<uint8_t> ser_val;

	// serialize the value into the buffer
	s.serialize(buf, val1);

	// move contents of the buffer to a vector
	ser_val.resize(buf.size());
	buf.read(ser_val.data(), ser_val.size());

	if (ser_val != ser_exp)
		throw std::logic_error("Serialized value does not match reference");

	test_unserialize(ser_val, val1);
}

int main()
{
	// Spec-provided examples
	test_serialize<opc_ua::Boolean>(false, {0});
	test_serialize<opc_ua::Boolean>(true, {1});
	test_unserialize<opc_ua::Boolean>({122}, true);
	test_serialize<opc_ua::UInt32>(1000000000, {0x00, 0xCA, 0x9A, 0x3B});
	test_serialize<opc_ua::String>(u8"水Boy", {0x06, 0x00, 0x00, 0x00, 0xE6, 0xB0, 0xB4, 0x42, 0x6F, 0x79});
	test_serialize<opc_ua::GUID>(
			{0x72, 0x96, 0x2B, 0x91, 0xFA, 0x75, 0x4A, 0xE6, 0x8D, 0x28, 0xB4, 0x04, 0xDC, 0x7D, 0xAF, 0x63},
			{0x91, 0x2B, 0x96, 0x72, 0x75, 0xFA, 0xE6, 0x4A, 0x8D, 0x28, 0xB4, 0x04, 0xDC, 0x7D, 0xAF, 0x63});
	test_serialize<opc_ua::NodeId>(
			opc_ua::NodeId(u8"Hot水", 1),
			{0x03, 0x01, 0x00, 0x06, 0x00, 0x00, 0x00, 0x48, 0x6F, 0x74, 0xE6, 0xB0, 0xB4});
	test_serialize<opc_ua::NodeId>(opc_ua::NodeId(0x72), {0x00, 0x72});
	test_serialize<opc_ua::NodeId>(opc_ua::NodeId(1025, 5), {0x01, 0x05, 0x01, 0x04});

	return 0;
}
