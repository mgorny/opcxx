/* OPC UA protocol implementation
 * (c) 2014 Michał Górny
 * Licensed under the terms of the 2-clause BSD license
 */

#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif

#include "types.hxx"

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
	: type(NodeIdType::NUMERIC), ns(node_ns), id({ .as_int = node_id })
{
}
