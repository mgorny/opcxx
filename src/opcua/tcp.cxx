/* OPC UA protocol implementation
 * (c) 2014 Michał Górny
 * Licensed under the terms of the 2-clause BSD license
 */

#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif

#include "tcp.hxx"

#include <opcua/ids.hxx>

#include <cassert>
#include <cstdlib>
#include <stdexcept>

// Unix Epoch offset in seconds
static opc_ua::Int64 unix_epoch_s = 11644478640;

opc_ua::UInt32 opc_ua::tcp::MessageStream::sequence_number = 0;
opc_ua::UInt32 opc_ua::tcp::MessageStream::next_request_id = 0;

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

opc_ua::tcp::TransportStream::TransportStream(event_base* ev)
	: bev(bufferevent_socket_new(ev, -1, BEV_OPT_CLOSE_ON_FREE)),
	in_ctx(bufferevent_get_input(bev)),
	out_ctx(bufferevent_get_output(bev)),
	connected(false), got_header(false)
{
	assert(bev);

	bufferevent_setcb(bev, read_handler, 0, 0, this);
	bufferevent_enable(bev, EV_READ);
}

opc_ua::tcp::TransportStream::~TransportStream()
{
	bufferevent_free(bev);
}

void opc_ua::tcp::TransportStream::connect_hostname(const char* hostname, uint16_t port, const char* endpoint, sa_family_t family)
{
	if (bufferevent_socket_connect_hostname(bev, 0, family, hostname, port))
		throw std::runtime_error("Connect failed prematurely (hostname resolution?)");

	// say hello after connecting
	HelloMessage hello = {
		.protocol_version = 0,
		// our buffers are pretty much unlimited thanks to libevent
		.receive_buffer_size = 0x100000,
		.send_buffer_size = 0x100000,
		.max_message_size = 0,
		.max_chunk_count = 0,
		.endpoint_url = endpoint,
	};

	TemporarySerializationContext sctx;
	BinarySerializer srl;
	srl.serialize(sctx, hello);
	write_message(MessageType::HEL, MessageIsFinal::FINAL, sctx);
}

void opc_ua::tcp::TransportStream::read_handler(bufferevent* bev, void* ctx)
{
	BinarySerializer srl;
	TransportStream* s = static_cast<TransportStream*>(ctx);

	if (!s->got_header)
	{
		// wait for complete header
		if (s->in_ctx.size() < s->h.serialized_length)
			return;

		srl.unserialize(s->in_ctx, s->h);
		s->got_header = true;

		// pass-through in case we got the message body too
	}

	// wait for complete body
	if (s->in_ctx.size() < s->h.message_size - s->h.serialized_length)
		return;

	TemporarySerializationContext buf;
	buf.move(s->in_ctx, s->h.message_size - s->h.serialized_length);

	// process the message
	switch (s->h.message_type)
	{
		case MessageType::ACK:
		{
			srl.unserialize(buf, s->remote_limits);

			s->connected = true;
			// push queued requests
			for (auto ms : s->secure_channel_queue)
				ms->request_secure_channel();

			break;
		}

		case MessageType::ERR:
		{
			ErrorMessage err;
			srl.unserialize(buf, err);

			throw std::runtime_error("ERR message received");
			break;
		}

		case MessageType::OPN:
		{
			UInt32 secure_channel_id;
			srl.unserialize(buf, secure_channel_id);

			std::vector<Byte> data_copy(buf.size());
			buf.read(data_copy.data(), data_copy.size());

			for (auto i = s->secure_channel_queue.begin();; ++i)
			{
				if (i == s->secure_channel_queue.end())
					throw std::runtime_error("Received open secure channel response with no matching request");

				MessageStream* ms = *i;

				// copy the current input into a local buffer
				TemporarySerializationContext copy_buf;
				copy_buf.write(data_copy.data(), data_copy.size());

				if (ms->process_secure_channel_response(copy_buf))
				{
#if 0 // fails (because of extra padding size field?)
					if (copy_buf.size() != 0)
						throw std::runtime_error("Part of message not unserialized in process_secure_channel_response()");
#endif

					// request matched, let's activate the channel
					s->secure_channel_queue.erase(i);
					s->secure_channels[secure_channel_id] = ms;
					break;
				}
			}

			break;
		}

		case MessageType::CLO:
		case MessageType::MSG:
//			s->msg_callback(s->h, s->in_ctx, s->callback_data);
			break;

		default:
			assert(not_reached);
	}

	if (buf.size() != 0)
		throw std::runtime_error("Part of message not unserialized");

	// prepare for the next message
	s->got_header = false;
}

void opc_ua::tcp::TransportStream::write_message(MessageType msg_type, MessageIsFinal is_final, SerializationContext& msg)
{
	BinarySerializer srl;

	switch (msg_type)
	{
		case MessageType::HEL:
		case MessageType::ACK:
		case MessageType::ERR:
		{
			MessageHeader h;
			h.message_type = msg_type;
			h.is_final = is_final;
			h.message_size = h.serialized_length + msg.size();
			srl.serialize(out_ctx, h);
			break;
		}
		case MessageType::OPN:
		case MessageType::CLO:
		case MessageType::MSG:
		{
			SecureConversationMessageHeader h;
			h.message_type = msg_type;
			h.is_final = is_final;
			h.message_size = h.serialized_length + msg.size();
			// TODO: real id for CLO & MSG
			h.secure_channel_id = 0;
			srl.serialize(out_ctx, h);
			break;
		}
		default:
			assert(not_reached);
	}

	out_ctx.write(msg);
}

void opc_ua::tcp::TransportStream::add_secure_channel(MessageStream& ms)
{
	secure_channel_queue.push_back(&ms);
	if (connected)
		ms.request_secure_channel();
}

opc_ua::tcp::MessageStream::MessageStream(TransportStream& new_ts)
	: ts(new_ts)
{
	ts.add_secure_channel(*this);
}

opc_ua::tcp::MessageStream::~MessageStream()
{
}

void opc_ua::tcp::MessageStream::request_secure_channel()
{
	TemporarySerializationContext sctx;
	BinarySerializer srl;

	AsymmetricAlgorithmSecurityHeader sech = {
		.security_policy_uri = "http://opcfoundation.org/UA/SecurityPolicy#None",
		.sender_certificate = "",
		.receiver_certificate_thumbprint = "",
	};
	srl.serialize(sctx, sech);

	SequenceHeader seqh = {
		.sequence_number = sequence_number++,
		.request_id = next_request_id++,
	};
	srl.serialize(sctx, seqh);

	channel_request_id = seqh.request_id;

	OpenSecureChannelRequest req(channel_request_id, SecurityTokenRequestType::ISSUE,
			MessageSecurityMode::NONE, "", 360000);
	NodeId req_id(static_cast<UInt32>(NumericNodeId::OPEN_SECURE_CHANNEL_REQUEST));

	srl.serialize(sctx, req_id);
	srl.serialize(sctx, req);

	ts.write_message(MessageType::OPN, MessageIsFinal::FINAL, sctx);
}

bool opc_ua::tcp::MessageStream::process_secure_channel_response(SerializationContext& sctx)
{
	BinarySerializer srl;
	AsymmetricAlgorithmSecurityHeader sech;
	srl.unserialize(sctx, sech);

	SequenceHeader seqh;
	srl.unserialize(sctx, seqh);

	OpenSecureChannelResponse resp;
	NodeId resp_id;

	srl.unserialize(sctx, resp_id);
	if (resp_id.type != NodeIdType::NUMERIC || resp_id.id.as_int != static_cast<UInt32>(NumericNodeId::OPEN_SECURE_CHANNEL_RESPONSE))
		throw std::runtime_error("Unknown response for OPN");

	srl.unserialize(sctx, resp);

	// was this our request?
	return (seqh.request_id == channel_request_id);
}
