/* OPC UA protocol implementation
 * (c) 2014 Michał Górny
 * Licensed under the terms of the 2-clause BSD license
 */

#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif

#include "types.hxx"

#include <cassert>
#include <random>

opc_ua::DateTime::DateTime()
	: ts({ .tv_sec = 0, .tv_nsec = 0})
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

bool opc_ua::DateTime::operator==(DateTime other) const
{
	return ts.tv_sec == other.ts.tv_sec && ts.tv_nsec == other.ts.tv_nsec;
}

bool opc_ua::DateTime::operator!=(DateTime other) const
{
	return ts.tv_sec != other.ts.tv_sec || ts.tv_nsec != other.ts.tv_nsec;
}

opc_ua::GUID::GUID()
	: guid{{0}}
{
}

opc_ua::GUID opc_ua::GUID::random_guid()
{
	// based on RFC4122, sect. 4.4

	std::random_device rnd("/dev/random");
	std::uniform_int_distribution<Byte> dist;

	GUID out;
	// fill in with random bytes
	for (auto& i : out.guid)
		i = dist(rnd);

	// clear variant and version bitfields
	out.guid[8] &= ~0xc0;
	out.guid[6] &= ~0xf0;
	// set variant and version
	out.guid[8] |= 0x80; // guid variant, 2 msbs
	out.guid[6] |= 0x40; // version 4 (randomly-generated), 4 msbs

	return out;
}

bool opc_ua::GUID::operator==(const GUID& other) const
{
	return guid == other.guid;
}

bool opc_ua::GUID::operator!=(const GUID& other) const
{
	return guid != other.guid;
}

opc_ua::NodeId::NodeId(UInt32 node_id, UInt16 node_ns)
	: type(NodeIdType::NUMERIC), ns(node_ns), as_int(node_id)
{
}

opc_ua::NodeId::NodeId(const GUID& node_id, UInt16 node_ns)
	: type(NodeIdType::GUID), ns(node_ns), as_guid(node_id)
{
}

opc_ua::NodeId::NodeId(const CharArray& node_id, UInt16 node_ns)
	: type(NodeIdType::STRING), ns(node_ns), as_chararray(node_id)
{
}

opc_ua::NodeId::NodeId(const ByteString& node_id, UInt16 node_ns, int unused)
	: type(NodeIdType::BYTE_STRING), ns(node_ns), as_bytestring(node_id)
{
}

bool opc_ua::NodeId::operator==(const NodeId& other) const
{
	if (type != other.type)
		return false;

	switch (type)
	{
		case NodeIdType::NUMERIC:
			return as_int == other.as_int;
		case NodeIdType::STRING:
			return as_chararray == other.as_chararray;
		case NodeIdType::GUID:
			return as_guid == other.as_guid;
		case NodeIdType::BYTE_STRING:
			return as_bytestring == other.as_bytestring;
		default:
			assert(not_reached);
	}
}

bool opc_ua::NodeId::operator!=(const NodeId& other) const
{
	return !(*this == other);
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

opc_ua::ExtensionObject::ExtensionObject(std::unique_ptr<Struct> obj)
	: inner_object(std::move(obj))
{
}

opc_ua::Variant::Variant()
	: variant_type(VariantType::NONE)
{
}

opc_ua::Variant::Variant(Boolean b)
	: variant_type(VariantType::BOOLEAN), as_boolean(b)
{
}

opc_ua::Variant::Variant(Byte b)
	: variant_type(VariantType::BYTE), as_byte(b)
{
}

opc_ua::Variant::Variant(UInt16 i)
	: variant_type(VariantType::UINT16), as_uint16(i)
{
}

opc_ua::Variant::Variant(Int32 i)
	: variant_type(VariantType::INT32), as_int32(i)
{
}

opc_ua::Variant::Variant(UInt32 i)
	: variant_type(VariantType::UINT32), as_uint32(i)
{
}

opc_ua::Variant::Variant(Int64 i)
	: variant_type(VariantType::INT64), as_int64(i)
{
}

opc_ua::Variant::Variant(Double f)
	: variant_type(VariantType::DOUBLE), as_double(f)
{
}

opc_ua::Variant::Variant(const String& s)
	: variant_type(VariantType::STRING), as_string(s)
{
}

opc_ua::Variant::Variant(DateTime dt)
	: variant_type(VariantType::DATETIME), as_datetime(dt)
{
}

opc_ua::Variant::Variant(const GUID& g)
	: variant_type(VariantType::GUID), as_guid(g)
{
}

opc_ua::Variant::Variant(const ByteString& s, int unused)
	: variant_type(VariantType::BYTESTRING), as_bytestring(s)
{
}

bool opc_ua::Variant::operator==(const Variant& other) const
{
	if (variant_type != other.variant_type)
		return false;

	switch (variant_type)
	{
		case VariantType::NONE:
			return true;
		case VariantType::BOOLEAN:
			return as_boolean == other.as_boolean;
		case VariantType::BYTE:
			return as_byte == other.as_byte;
		case VariantType::UINT16:
			return as_uint16 == other.as_uint16;
		case VariantType::INT32:
			return as_int32 == other.as_int32;
		case VariantType::UINT32:
			return as_uint32 == other.as_uint32;
		case VariantType::INT64:
			return as_int64 == other.as_int64;
		case VariantType::DOUBLE:
			return as_double == other.as_double;
		case VariantType::STRING:
			return as_string == other.as_string;
		case VariantType::DATETIME:
			return as_datetime == other.as_datetime;
		case VariantType::GUID:
			return as_guid == other.as_guid;
		case VariantType::BYTESTRING:
			return as_bytestring == other.as_bytestring;
		default:
			assert(not_reached);
	}
}

bool opc_ua::Variant::operator!=(const Variant& other) const
{
	return !(*this == other);
}
