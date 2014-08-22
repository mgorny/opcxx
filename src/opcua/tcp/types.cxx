/* OPC UA protocol implementation
 * (c) 2014 Michał Górny
 * Licensed under the terms of the 2-clause BSD license
 */

#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif

#include "types.hxx"

#include <opcua/tcp/idmapping.hxx>

#include <cassert>
#include <cstdlib>
#include <stdexcept>

// Unix Epoch offset in seconds
static opc_ua::Int64 unix_epoch_s = 11644478640;

void opc_ua::tcp::BinarySerializer::serialize(WritableSerializationBuffer& ctx, Boolean b)
{
	Byte i = b ? 1 : 0;

	ctx.write(&i, sizeof(i));
}

void opc_ua::tcp::BinarySerializer::serialize(WritableSerializationBuffer& ctx, Byte i)
{
	ctx.write(&i, sizeof(i));
}

void opc_ua::tcp::BinarySerializer::serialize(WritableSerializationBuffer& ctx, UInt16 i)
{
	ctx.write(&i, sizeof(i));
}

void opc_ua::tcp::BinarySerializer::serialize(WritableSerializationBuffer& ctx, UInt32 i)
{
	ctx.write(&i, sizeof(i));
}

void opc_ua::tcp::BinarySerializer::serialize(WritableSerializationBuffer& ctx, Int32 i)
{
	ctx.write(&i, sizeof(i));
}

void opc_ua::tcp::BinarySerializer::serialize(WritableSerializationBuffer& ctx, Int64 i)
{
	ctx.write(&i, sizeof(i));
}

void opc_ua::tcp::BinarySerializer::serialize(WritableSerializationBuffer& ctx, Double f)
{
	ctx.write(&f, sizeof(f));
}

void opc_ua::tcp::BinarySerializer::serialize(WritableSerializationBuffer& ctx, const String& s)
{
	Int32 s_len = s.size();
	// TODO: allow proper distinction between null & empty string
	if (s_len == 0)
		s_len = -1;
	serialize(ctx, s_len);
	if (s_len > 0)
		ctx.write(s.c_str(), s_len);
}

void opc_ua::tcp::BinarySerializer::serialize(WritableSerializationBuffer& ctx, DateTime t)
{
	// convert time_t to seconds since 1601-01-01
	Int64 secs = unix_epoch_s + t.ts.tv_sec;
	// and then to hundreds of nanoseconds, and add the remainder
	Int64 ts = secs * 1E7 + (t.ts.tv_nsec / 100);

	// the spec doesn't allow values earlier than 1601-01-01
	if (ts < 0)
		ts = 0;

	serialize(ctx, ts);
}

struct LocalizedTextEncodingMask
{
	static constexpr opc_ua::Byte LOCALE_SPECIFIED = 0x01;
	static constexpr opc_ua::Byte TEXT_SPECIFIED = 0x02;
};

void opc_ua::tcp::BinarySerializer::serialize(WritableSerializationBuffer& ctx, const LocalizedText& s)
{
	Byte flags = 0;

	if (!s.locale.empty())
		flags |= LocalizedTextEncodingMask::LOCALE_SPECIFIED;
	if (!s.text.empty())
		flags |= LocalizedTextEncodingMask::TEXT_SPECIFIED;

	serialize(ctx, flags);
	if (!s.locale.empty())
		serialize(ctx, s.locale);
	if (!s.text.empty())
		serialize(ctx, s.text);
}

void opc_ua::tcp::BinarySerializer::serialize(WritableSerializationBuffer& ctx, const GUID& g)
{
	// first 8 bytes go as little-endian integers
	UInt32 data1 = g.guid[0] << 24 | g.guid[1] << 16 | g.guid[2] << 8 | g.guid[3];
	UInt16 data2 = g.guid[4] << 8 | g.guid[5];
	UInt16 data3 = g.guid[6] << 8 | g.guid[7];
	// last 8 bytes go as bytes
	const Byte* data4 = &g.guid[8];

	serialize(ctx, data1);
	serialize(ctx, data2);
	serialize(ctx, data3);
	ctx.write(data4, 8);
}

void opc_ua::tcp::BinarySerializer::serialize(WritableSerializationBuffer& ctx, const NodeId& n)
{
	switch (n.type)
	{
		case NodeIdType::NUMERIC:
		{
			// id can be encoded as two-byte id
			if (n.as_int <= 0xff)
			{
				serialize(ctx, static_cast<Byte>(BinaryNodeIdType::TWO_BYTE));
				serialize(ctx, static_cast<Byte>(n.as_int));
			}
			else if (n.ns <= 0xff && n.as_int <= 0xffff)
			{
				serialize(ctx, static_cast<Byte>(BinaryNodeIdType::FOUR_BYTE));
				serialize(ctx, static_cast<Byte>(n.ns));
				serialize(ctx, static_cast<UInt16>(n.as_int));
			}
			else
			{
				serialize(ctx, static_cast<Byte>(BinaryNodeIdType::NUMERIC));
				serialize(ctx, n.ns);
				serialize(ctx, n.as_int);
			}

			break;
		}
		case NodeIdType::GUID:
		{
			serialize(ctx, static_cast<Byte>(BinaryNodeIdType::GUID));
			serialize(ctx, n.ns);
			serialize(ctx, n.as_guid);
			break;
		}
		case NodeIdType::STRING:
		{
			serialize(ctx, static_cast<Byte>(BinaryNodeIdType::STRING));
			serialize(ctx, n.ns);
			serialize(ctx, n.as_chararray);
			break;
		}
		case NodeIdType::BYTE_STRING:
		{
			serialize(ctx, static_cast<Byte>(BinaryNodeIdType::BYTE_STRING));
			serialize(ctx, n.ns);
			serialize(ctx, n.as_bytestring);
			break;
		}
		default:
			assert(not_reached);
	}
}

void opc_ua::tcp::BinarySerializer::serialize(WritableSerializationBuffer& ctx, const Struct& s)
{
	s.serialize(ctx, *this);
}

void opc_ua::tcp::BinarySerializer::serialize(WritableSerializationBuffer& ctx, const ExtensionObject& s)
{
	if (!s.inner_object)
	{
		serialize(ctx, NodeId(0));
		serialize(ctx, Byte(0));
	}
	else
	{
		NodeId orig_id(s.inner_object.get()->get_node_id());

		if (orig_id.type != NodeIdType::NUMERIC || orig_id.ns != 0)
			throw std::runtime_error("Non-standard objects in ExtensionObject not supported");

		NodeId mapped_id(id_mapping.at(orig_id.as_int));

		MemorySerializationBuffer lctx;
		// serialize to buffer to obtain length
		s.inner_object.get()->serialize(lctx, *this);

		serialize(ctx, mapped_id);
		serialize(ctx, Byte(1));
		serialize(ctx, static_cast<UInt32>(lctx.size()));
		ctx.move(lctx);
	}
}

void opc_ua::tcp::BinarySerializer::serialize(WritableSerializationBuffer& ctx, const Variant& v)
{
	Byte encoding_mask;

	encoding_mask = static_cast<Byte>(v.variant_type);
	serialize(ctx, encoding_mask);

	switch (v.variant_type)
	{
		case VariantType::BOOLEAN:
			serialize(ctx, v.as_boolean);
			break;
		case VariantType::BYTE:
			serialize(ctx, v.as_byte);
			break;
		case VariantType::UINT16:
			serialize(ctx, v.as_uint16);
			break;
		case VariantType::INT32:
			serialize(ctx, v.as_int32);
			break;
		case VariantType::UINT32:
			serialize(ctx, v.as_uint32);
			break;
		case VariantType::INT64:
			serialize(ctx, v.as_int64);
			break;
		case VariantType::DOUBLE:
			serialize(ctx, v.as_double);
			break;
		case VariantType::STRING:
			serialize(ctx, v.as_string);
			break;
		case VariantType::DATETIME:
			serialize(ctx, v.as_datetime);
			break;
		case VariantType::GUID:
			serialize(ctx, v.as_guid);
			break;
		case VariantType::BYTESTRING:
			serialize(ctx, v.as_bytestring);
			break;
		default:
			throw std::runtime_error("Unsupported variant type");
	}
}

void opc_ua::tcp::BinarySerializer::serialize(WritableSerializationBuffer& ctx, MessageType t)
{
	UInt32 as_uint = static_cast<UInt32>(t);
	ctx.write(&as_uint, sizeof(Byte)*3);
}

void opc_ua::tcp::BinarySerializer::serialize(WritableSerializationBuffer& ctx, MessageIsFinal b)
{
	Byte as_byte = static_cast<Byte>(b);
	ctx.write(&as_byte, sizeof(as_byte));
}

void opc_ua::tcp::BinarySerializer::serialize(WritableSerializationBuffer& ctx, const MessageHeader& h)
{
	serialize(ctx, h.message_type);
	serialize(ctx, h.is_final);
	serialize(ctx, h.message_size);
}

void opc_ua::tcp::BinarySerializer::serialize(WritableSerializationBuffer& ctx, const SecureConversationMessageHeader& h)
{
	serialize(ctx, static_cast<const MessageHeader&>(h));
	serialize(ctx, h.secure_channel_id);
}

void opc_ua::tcp::BinarySerializer::serialize(WritableSerializationBuffer& ctx, const HelloMessage& msg)
{
	if (msg.endpoint_url.size() >= 4096)
		throw std::runtime_error("Endpoint URL length exceeds 4096 bytes");

	serialize(ctx, msg.protocol_version);
	serialize(ctx, msg.receive_buffer_size);
	serialize(ctx, msg.send_buffer_size);
	serialize(ctx, msg.max_message_size);
	serialize(ctx, msg.max_chunk_count);
	serialize(ctx, msg.endpoint_url);
}

void opc_ua::tcp::BinarySerializer::serialize(WritableSerializationBuffer& ctx, const AcknowledgeMessage& msg)
{
	serialize(ctx, msg.protocol_version);
	serialize(ctx, msg.receive_buffer_size);
	serialize(ctx, msg.send_buffer_size);
	serialize(ctx, msg.max_message_size);
	serialize(ctx, msg.max_chunk_count);
}

void opc_ua::tcp::BinarySerializer::serialize(WritableSerializationBuffer& ctx, const ErrorMessage& msg)
{
	serialize(ctx, msg.error);
	serialize(ctx, msg.reason);
}

void opc_ua::tcp::BinarySerializer::serialize(WritableSerializationBuffer& ctx, const AsymmetricAlgorithmSecurityHeader& h)
{
	serialize(ctx, h.security_policy_uri);
	serialize(ctx, h.sender_certificate);
	serialize(ctx, h.receiver_certificate_thumbprint);
}

void opc_ua::tcp::BinarySerializer::serialize(WritableSerializationBuffer& ctx, const SymmetricAlgorithmSecurityHeader& h)
{
	serialize(ctx, h.token_id);
}

void opc_ua::tcp::BinarySerializer::serialize(WritableSerializationBuffer& ctx, const SequenceHeader& h)
{
	serialize(ctx, h.sequence_number);
	serialize(ctx, h.request_id);
}

void opc_ua::tcp::BinarySerializer::serialize(WritableSerializationBuffer& ctx, const AbstractArraySerialization& a)
{
	Int32 a_len = a.size();
	// TODO: allow proper distinction between null & empty array
	if (a_len == 0)
		a_len = -1;
	serialize(ctx, a_len);

	a.serialize_all(ctx, *this);
}

void opc_ua::tcp::BinarySerializer::unserialize(ReadableSerializationBuffer& ctx, Boolean& b)
{
	Byte i;
	ctx.read(&i, sizeof(i));

	b = !!i;
}

void opc_ua::tcp::BinarySerializer::unserialize(ReadableSerializationBuffer& ctx, Byte& i)
{
	ctx.read(&i, sizeof(i));
}

void opc_ua::tcp::BinarySerializer::unserialize(ReadableSerializationBuffer& ctx, UInt16& i)
{
	ctx.read(&i, sizeof(i));
}

void opc_ua::tcp::BinarySerializer::unserialize(ReadableSerializationBuffer& ctx, UInt32& i)
{
	ctx.read(&i, sizeof(i));
}

void opc_ua::tcp::BinarySerializer::unserialize(ReadableSerializationBuffer& ctx, Int32& i)
{
	ctx.read(&i, sizeof(i));
}

void opc_ua::tcp::BinarySerializer::unserialize(ReadableSerializationBuffer& ctx, Int64& i)
{
	ctx.read(&i, sizeof(i));
}

void opc_ua::tcp::BinarySerializer::unserialize(ReadableSerializationBuffer& ctx, Double& f)
{
	ctx.read(&f, sizeof(f));
}

void opc_ua::tcp::BinarySerializer::unserialize(ReadableSerializationBuffer& ctx, String& s)
{
	Int32 length;
	ctx.read(&length, sizeof(length));

	s.clear();
	if (length != -1)
	{
		// XXX: very ugly
		char buf[length];
		ctx.read(buf, length);

		s.append(buf, length);
	}
}

void opc_ua::tcp::BinarySerializer::unserialize(ReadableSerializationBuffer& ctx, DateTime& t)
{
	Int64 ts;
	unserialize(ctx, ts);

	// first, take the ns part
	t.ts.tv_nsec = (ts % static_cast<Int64>(1E7)) * 100;
	// shift it down to seconds
	ts /= 1E7;
	// and readjust to unix Epoch
	t.ts.tv_sec = ts - unix_epoch_s;
}

void opc_ua::tcp::BinarySerializer::unserialize(ReadableSerializationBuffer& ctx, LocalizedText& s)
{
	Byte flags;

	unserialize(ctx, flags);

	if (flags & LocalizedTextEncodingMask::LOCALE_SPECIFIED)
		unserialize(ctx, s.locale);
	else
		s.locale.clear();

	if (flags & LocalizedTextEncodingMask::TEXT_SPECIFIED)
		unserialize(ctx, s.text);
	else
		s.text.clear();
}

void opc_ua::tcp::BinarySerializer::unserialize(ReadableSerializationBuffer& ctx, GUID& g)
{
	UInt32 data1;
	UInt16 data2;
	UInt16 data3;

	unserialize(ctx, data1);
	unserialize(ctx, data2);
	unserialize(ctx, data3);

	// first 8 bytes go as little-endian integers
	g.guid[0] = (data1 >> 24) & 0xff;
	g.guid[1] = (data1 >> 16) & 0xff;
	g.guid[2] = (data1 >> 8) & 0xff;
	g.guid[3] = data1 & 0xff;
	g.guid[4] = (data2 >> 8) & 0xff;
	g.guid[5] = data2 & 0xff;
	g.guid[6] = (data3 >> 8) & 0xff;
	g.guid[7] = data3 & 0xff;

	// last 8 bytes go as bytes
	ctx.read(&g.guid[8], 8);
}

void opc_ua::tcp::BinarySerializer::unserialize(ReadableSerializationBuffer& ctx, NodeId& n)
{
	Byte node_type;

	unserialize(ctx, node_type);

	switch (static_cast<BinaryNodeIdType>(node_type))
	{
		case BinaryNodeIdType::TWO_BYTE:
		{
			Byte id;
			unserialize(ctx, id);
			n = NodeId(id, 0);
			break;
		}
		case BinaryNodeIdType::FOUR_BYTE:
		{
			Byte ns;
			UInt16 id;
			unserialize(ctx, ns);
			unserialize(ctx, id);
			n = NodeId(id, ns);
			break;
		}
		case BinaryNodeIdType::NUMERIC:
		{
			UInt16 ns;
			UInt32 id;
			unserialize(ctx, ns);
			unserialize(ctx, id);
			n = NodeId(id, ns);
			break;
		}
		case BinaryNodeIdType::GUID:
		{
			UInt16 ns;
			GUID guid;
			unserialize(ctx, ns);
			unserialize(ctx, guid);
			n = NodeId(guid, ns);
			break;
		}
		case BinaryNodeIdType::STRING:
		{
			UInt16 ns;
			CharArray id;
			unserialize(ctx, ns);
			unserialize(ctx, id);
			n = NodeId(id, ns);
			break;
		}
		case BinaryNodeIdType::BYTE_STRING:
		{
			UInt16 ns;
			ByteString id;
			unserialize(ctx, ns);
			unserialize(ctx, id);
			n = NodeId(id, ns, 0);
			break;
		}
		default:
			assert(not_reached);
	}
}

void opc_ua::tcp::BinarySerializer::unserialize(ReadableSerializationBuffer& ctx, Struct& s)
{
	s.unserialize(ctx, *this);
}

void opc_ua::tcp::BinarySerializer::unserialize(ReadableSerializationBuffer& ctx, ExtensionObject& s)
{
	// Note: extension objects are not supported now.
	NodeId id;
	Byte encoding;

	unserialize(ctx, id);
	unserialize(ctx, encoding);

	if (id == NodeId(0))
		s.inner_object.reset(nullptr);
	else
	{
		if (encoding != 1)
			throw std::runtime_error("Unsupported encoding of ExtensionObject");
		if (id.type != NodeIdType::NUMERIC)
			throw std::runtime_error("Non-numeric NodeIDs are not supported");
		if (id.ns != 0)
			throw std::runtime_error("Non-standard namespaces are not supported");

		UInt32 base_id = reverse_id_mapping.at(id.as_int);
		s.inner_object.reset(struct_constructors.at(base_id)());

		UInt32 length;
		unserialize(ctx, length);

		MemorySerializationBuffer buf;
		buf.move(ctx, length);

		s.inner_object.get()->unserialize(buf, *this);
	}
}

void opc_ua::tcp::BinarySerializer::unserialize(ReadableSerializationBuffer& ctx, Variant& v)
{
	Byte encoding_mask;
	VariantType vtype;
	bool is_array;

	unserialize(ctx, encoding_mask);
	is_array = encoding_mask & 0x80;
	vtype = static_cast<VariantType>(encoding_mask & ~0x80);

	if (is_array)
		throw std::runtime_error("Variant arrays unsupported");

	switch (vtype)
	{
		case VariantType::BOOLEAN:
			unserialize(ctx, v.as_boolean);
			break;
		case VariantType::BYTE:
			unserialize(ctx, v.as_byte);
			break;
		case VariantType::UINT16:
			unserialize(ctx, v.as_uint16);
			break;
		case VariantType::INT32:
			unserialize(ctx, v.as_int32);
			break;
		case VariantType::UINT32:
			unserialize(ctx, v.as_uint32);
			break;
		case VariantType::INT64:
			unserialize(ctx, v.as_int64);
			break;
		case VariantType::DOUBLE:
			unserialize(ctx, v.as_double);
			break;
		case VariantType::STRING:
			unserialize(ctx, v.as_string);
			break;
		case VariantType::DATETIME:
			unserialize(ctx, v.as_datetime);
			break;
		case VariantType::GUID:
			unserialize(ctx, v.as_guid);
			break;
		case VariantType::BYTESTRING:
			unserialize(ctx, v.as_bytestring);
			break;
		default:
			throw std::runtime_error("Unsupported variant type");
	}
	v.variant_type = vtype;
}

void opc_ua::tcp::BinarySerializer::unserialize(ReadableSerializationBuffer& ctx, MessageIsFinal& b)
{
	Byte as_byte;
	ctx.read(&as_byte, sizeof(as_byte));

	b = static_cast<MessageIsFinal>(as_byte);
}

void opc_ua::tcp::BinarySerializer::unserialize(ReadableSerializationBuffer& ctx, MessageType& t)
{
	UInt32 as_uint = 0;
	ctx.read(&as_uint, sizeof(Byte)*3);

	t = static_cast<MessageType>(as_uint);
}

void opc_ua::tcp::BinarySerializer::unserialize(ReadableSerializationBuffer& ctx, MessageHeader& h)
{
	unserialize(ctx, h.message_type);
	unserialize(ctx, h.is_final);
	unserialize(ctx, h.message_size);
}

void opc_ua::tcp::BinarySerializer::unserialize(ReadableSerializationBuffer& ctx, HelloMessage& msg)
{
	unserialize(ctx, msg.protocol_version);
	unserialize(ctx, msg.receive_buffer_size);
	unserialize(ctx, msg.send_buffer_size);
	unserialize(ctx, msg.max_message_size);
	unserialize(ctx, msg.max_chunk_count);
	unserialize(ctx, msg.endpoint_url);
}

void opc_ua::tcp::BinarySerializer::unserialize(ReadableSerializationBuffer& ctx, AcknowledgeMessage& msg)
{
	unserialize(ctx, msg.protocol_version);
	unserialize(ctx, msg.receive_buffer_size);
	unserialize(ctx, msg.send_buffer_size);
	unserialize(ctx, msg.max_message_size);
	unserialize(ctx, msg.max_chunk_count);
}

void opc_ua::tcp::BinarySerializer::unserialize(ReadableSerializationBuffer& ctx, ErrorMessage& msg)
{
	unserialize(ctx, msg.error);
	unserialize(ctx, msg.reason);
}

void opc_ua::tcp::BinarySerializer::unserialize(ReadableSerializationBuffer& ctx, AsymmetricAlgorithmSecurityHeader& h)
{
	unserialize(ctx, h.security_policy_uri);
	unserialize(ctx, h.sender_certificate);
	unserialize(ctx, h.receiver_certificate_thumbprint);
}

void opc_ua::tcp::BinarySerializer::unserialize(ReadableSerializationBuffer& ctx, SymmetricAlgorithmSecurityHeader& h)
{
	unserialize(ctx, h.token_id);
}

void opc_ua::tcp::BinarySerializer::unserialize(ReadableSerializationBuffer& ctx, SequenceHeader& h)
{
	unserialize(ctx, h.sequence_number);
	unserialize(ctx, h.request_id);
}

void opc_ua::tcp::BinarySerializer::unserialize(ReadableSerializationBuffer& ctx, const AbstractArrayUnserialization& a)
{
	Int32 length;
	ctx.read(&length, sizeof(length));

	a.clear();
	if (length > 0)
		a.unserialize_n(ctx, *this, length);
}
