/* OPC UA protocol implementation
 * (c) 2014 Michał Górny
 * Licensed under the terms of the 2-clause BSD license
 */

#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif

#include "types.hxx"

#include <random>

opc_ua::DateTime::DateTime()
{
}

opc_ua::DateTime::DateTime(struct timespec new_ts)
	: ts(new_ts)
{
}

opc_ua::DateTime opc_ua::DateTime::now()
{
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);

	return DateTime(ts);
}

opc_ua::NodeId::NodeId()
{
}

opc_ua::NodeId::NodeId(UInt32 node_id, UInt16 node_ns)
	: type(NodeIdType::NUMERIC), ns(node_ns), as_int(node_id)
{
}

opc_ua::NodeId::NodeId(const GUID& node_id, UInt16 node_ns)
	: type(NodeIdType::GUID), ns(node_ns), as_guid(node_id)
{
}

opc_ua::NodeId::NodeId(const ByteString& node_id, UInt16 node_ns)
	: type(NodeIdType::BYTE_STRING), ns(node_ns), as_bytestring(node_id)
{
}

opc_ua::ByteString opc_ua::random_nonce()
{
	std::random_device rnd("/dev/random");
	std::uniform_int_distribution<opc_ua::Byte> dist;

	ByteString ret;
	for (int i = 0; i < 32; ++i)
		ret.push_back(dist(rnd));

	return std::move(ret);
}
