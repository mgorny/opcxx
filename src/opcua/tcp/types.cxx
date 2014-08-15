/* OPC UA protocol implementation
 * (c) 2014 Michał Górny
 * Licensed under the terms of the 2-clause BSD license
 */

#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif

#include "types.hxx"

#include <opcua/common/ids.hxx>

#include <cassert>
#include <cstdlib>
#include <stdexcept>

// Unix Epoch offset in seconds
static opc_ua::Int64 unix_epoch_s = 11644478640;

void opc_ua::tcp::BinarySerializer::serialize(SerializationContext& ctx, Byte i)
{
	ctx.write(&i, sizeof(i));
}

void opc_ua::tcp::BinarySerializer::serialize(SerializationContext& ctx, UInt16 i)
{
	ctx.write(&i, sizeof(i));
}

void opc_ua::tcp::BinarySerializer::serialize(SerializationContext& ctx, UInt32 i)
{
	ctx.write(&i, sizeof(i));
}

void opc_ua::tcp::BinarySerializer::serialize(SerializationContext& ctx, Int32 i)
{
	ctx.write(&i, sizeof(i));
}

void opc_ua::tcp::BinarySerializer::serialize(SerializationContext& ctx, Int64 i)
{
	ctx.write(&i, sizeof(i));
}

void opc_ua::tcp::BinarySerializer::serialize(SerializationContext& ctx, const String& s)
{
	Int32 s_len = s.size();
	// TODO: allow proper distinction between null & empty string
	if (s_len == 0)
		s_len = -1;
	serialize(ctx, s_len);
	if (s_len > 0)
		ctx.write(s.c_str(), s_len);
}

void opc_ua::tcp::BinarySerializer::serialize(SerializationContext& ctx, const Array<String>& a)
{
	Int32 a_len = a.size();
	// TODO: allow proper distinction between null & empty array
	if (a_len == 0)
		a_len = -1;
	serialize(ctx, a_len);

	for (auto& s : a)
		serialize(ctx, s);
}

void opc_ua::tcp::BinarySerializer::serialize(SerializationContext& ctx, DateTime t)
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

void opc_ua::tcp::BinarySerializer::serialize(SerializationContext& ctx, const NodeId& n)
{
	switch (n.type)
	{
		case NodeIdType::NUMERIC:
		{
			// id can be encoded as two-byte id
			if (n.id.as_int <= 0xff)
			{
				serialize(ctx, static_cast<Byte>(BinaryNodeIdType::TWO_BYTE));
				serialize(ctx, static_cast<Byte>(n.id.as_int));
			}
			else if (n.ns <= 0xff && n.id.as_int <= 0xffff)
			{
				serialize(ctx, static_cast<Byte>(BinaryNodeIdType::FOUR_BYTE));
				serialize(ctx, static_cast<Byte>(n.ns));
				serialize(ctx, static_cast<UInt16>(n.id.as_int));
			}
			else
			{
				serialize(ctx, static_cast<Byte>(BinaryNodeIdType::NUMERIC));
				serialize(ctx, static_cast<UInt16>(n.ns));
				serialize(ctx, static_cast<UInt32>(n.id.as_int));
			}

			break;
		}
		default:
			assert(not_reached);
	}
}

void opc_ua::tcp::BinarySerializer::serialize(SerializationContext& ctx, const Struct& s)
{
	s.serialize(ctx, *this);
}

void opc_ua::tcp::BinarySerializer::serialize(SerializationContext& ctx, const ExtensionObject& s)
{
	// Note: extension objects are not supported now.
	serialize(ctx, NodeId(0));
	serialize(ctx, Byte(0));
}

void opc_ua::tcp::BinarySerializer::serialize(SerializationContext& ctx, MessageType t)
{
	UInt32 as_uint = static_cast<UInt32>(t);
	ctx.write(&as_uint, sizeof(Byte)*3);
}

void opc_ua::tcp::BinarySerializer::serialize(SerializationContext& ctx, MessageIsFinal b)
{
	Byte as_byte = static_cast<Byte>(b);
	ctx.write(&as_byte, sizeof(as_byte));
}

void opc_ua::tcp::BinarySerializer::serialize(SerializationContext& ctx, const MessageHeader& h)
{
	serialize(ctx, h.message_type);
	serialize(ctx, h.is_final);
	serialize(ctx, h.message_size);
}

void opc_ua::tcp::BinarySerializer::serialize(SerializationContext& ctx, const SecureConversationMessageHeader& h)
{
	serialize(ctx, static_cast<const MessageHeader&>(h));
	serialize(ctx, h.secure_channel_id);
}

void opc_ua::tcp::BinarySerializer::serialize(SerializationContext& ctx, const HelloMessage& msg)
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

void opc_ua::tcp::BinarySerializer::serialize(SerializationContext& ctx, const AcknowledgeMessage& msg)
{
	serialize(ctx, msg.protocol_version);
	serialize(ctx, msg.receive_buffer_size);
	serialize(ctx, msg.send_buffer_size);
	serialize(ctx, msg.max_message_size);
	serialize(ctx, msg.max_chunk_count);
}

void opc_ua::tcp::BinarySerializer::serialize(SerializationContext& ctx, const ErrorMessage& msg)
{
	serialize(ctx, msg.error);
	serialize(ctx, msg.reason);
}

void opc_ua::tcp::BinarySerializer::serialize(SerializationContext& ctx, const AsymmetricAlgorithmSecurityHeader& h)
{
	serialize(ctx, h.security_policy_uri);
	serialize(ctx, h.sender_certificate);
	serialize(ctx, h.receiver_certificate_thumbprint);
}

void opc_ua::tcp::BinarySerializer::serialize(SerializationContext& ctx, const SymmetricAlgorithmSecurityHeader& h)
{
	serialize(ctx, h.token_id);
}

void opc_ua::tcp::BinarySerializer::serialize(SerializationContext& ctx, const SequenceHeader& h)
{
	serialize(ctx, h.sequence_number);
	serialize(ctx, h.request_id);
}

void opc_ua::tcp::BinarySerializer::unserialize(SerializationContext& ctx, Byte& i)
{
	ctx.read(&i, sizeof(i));
}

void opc_ua::tcp::BinarySerializer::unserialize(SerializationContext& ctx, UInt16& i)
{
	ctx.read(&i, sizeof(i));
}

void opc_ua::tcp::BinarySerializer::unserialize(SerializationContext& ctx, UInt32& i)
{
	ctx.read(&i, sizeof(i));
}

void opc_ua::tcp::BinarySerializer::unserialize(SerializationContext& ctx, Int32& i)
{
	ctx.read(&i, sizeof(i));
}

void opc_ua::tcp::BinarySerializer::unserialize(SerializationContext& ctx, Int64& i)
{
	ctx.read(&i, sizeof(i));
}

void opc_ua::tcp::BinarySerializer::unserialize(SerializationContext& ctx, String& s)
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

void opc_ua::tcp::BinarySerializer::unserialize(SerializationContext& ctx, Array<String>& a)
{
	Int32 length;
	ctx.read(&length, sizeof(length));

	a.clear();
	if (length != -1)
	{
		String s;
		unserialize(ctx, s);
		a.push_back(s);
	}
}

void opc_ua::tcp::BinarySerializer::unserialize(SerializationContext& ctx, DateTime& t)
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

void opc_ua::tcp::BinarySerializer::unserialize(SerializationContext& ctx, NodeId& n)
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
		default:
			assert(not_reached);
	}
}

void opc_ua::tcp::BinarySerializer::unserialize(SerializationContext& ctx, Struct& s)
{
	s.unserialize(ctx, *this);
}

void opc_ua::tcp::BinarySerializer::unserialize(SerializationContext& ctx, ExtensionObject& s)
{
	// Note: extension objects are not supported now.
	NodeId id;
	Byte encoding;

	unserialize(ctx, id);
	unserialize(ctx, encoding);

	if (id.type != NodeIdType::NUMERIC || id.ns != 0 || id.id.as_int != 0
			|| encoding != 0)
		throw std::runtime_error("ExtensionObjects are not supported at the moment");
}

void opc_ua::tcp::BinarySerializer::unserialize(SerializationContext& ctx, MessageIsFinal& b)
{
	Byte as_byte;
	ctx.read(&as_byte, sizeof(as_byte));

	b = static_cast<MessageIsFinal>(as_byte);
}

void opc_ua::tcp::BinarySerializer::unserialize(SerializationContext& ctx, MessageType& t)
{
	UInt32 as_uint = 0;
	ctx.read(&as_uint, sizeof(Byte)*3);

	t = static_cast<MessageType>(as_uint);
}

void opc_ua::tcp::BinarySerializer::unserialize(SerializationContext& ctx, MessageHeader& h)
{
	unserialize(ctx, h.message_type);
	unserialize(ctx, h.is_final);
	unserialize(ctx, h.message_size);
}

void opc_ua::tcp::BinarySerializer::unserialize(SerializationContext& ctx, HelloMessage& msg)
{
	unserialize(ctx, msg.protocol_version);
	unserialize(ctx, msg.receive_buffer_size);
	unserialize(ctx, msg.send_buffer_size);
	unserialize(ctx, msg.max_message_size);
	unserialize(ctx, msg.max_chunk_count);
	unserialize(ctx, msg.endpoint_url);
}

void opc_ua::tcp::BinarySerializer::unserialize(SerializationContext& ctx, AcknowledgeMessage& msg)
{
	unserialize(ctx, msg.protocol_version);
	unserialize(ctx, msg.receive_buffer_size);
	unserialize(ctx, msg.send_buffer_size);
	unserialize(ctx, msg.max_message_size);
	unserialize(ctx, msg.max_chunk_count);
}

void opc_ua::tcp::BinarySerializer::unserialize(SerializationContext& ctx, ErrorMessage& msg)
{
	unserialize(ctx, msg.error);
	unserialize(ctx, msg.reason);
}

void opc_ua::tcp::BinarySerializer::unserialize(SerializationContext& ctx, AsymmetricAlgorithmSecurityHeader& h)
{
	unserialize(ctx, h.security_policy_uri);
	unserialize(ctx, h.sender_certificate);
	unserialize(ctx, h.receiver_certificate_thumbprint);
}

void opc_ua::tcp::BinarySerializer::unserialize(SerializationContext& ctx, SequenceHeader& h)
{
	unserialize(ctx, h.sequence_number);
	unserialize(ctx, h.request_id);
}
