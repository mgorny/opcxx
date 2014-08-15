/* OPC UA protocol implementation
 * (c) 2014 Michał Górny
 * Licensed under the terms of the 2-clause BSD license
 */

#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif

#include "streams.hxx"

#include <opcua/tcp/idmapping.hxx>

#include <cassert>
#include <stdexcept>

opc_ua::UInt32 opc_ua::tcp::MessageStream::sequence_number = 0;
opc_ua::UInt32 opc_ua::tcp::MessageStream::next_request_id = 0;

opc_ua::tcp::TransportStream::TransportStream(event_base* ev)
	: bev(bufferevent_socket_new(ev, -1, BEV_OPT_CLOSE_ON_FREE)),
	in_ctx(bufferevent_get_input(bev)),
	out_ctx(bufferevent_get_output(bev)),
	connected(false), got_header(false)
{
	assert(bev);

	bufferevent_setcb(bev, read_handler, 0, event_handler, this);
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

				if (ms->process_secure_channel_response(copy_buf, secure_channel_id))
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

void opc_ua::tcp::TransportStream::event_handler(bufferevent* bev, short what, void* ctx)
{
	if (what & BEV_EVENT_EOF)
		throw std::runtime_error("Transport stream disconnected");
	if (what & BEV_EVENT_ERROR)
		throw std::runtime_error("Transport stream error");
}

void opc_ua::tcp::TransportStream::write_message(MessageType msg_type, MessageIsFinal is_final, SerializationContext& msg, UInt32 channel_id)
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
			h.secure_channel_id = channel_id;
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
	NodeId req_id(id_mapping.at(req.node_id()));

	srl.serialize(sctx, req_id);
	srl.serialize(sctx, req);

	ts.write_message(MessageType::OPN, MessageIsFinal::FINAL, sctx);
}

bool opc_ua::tcp::MessageStream::process_secure_channel_response(SerializationContext& sctx, UInt32 channel_id)
{
	BinarySerializer srl;
	AsymmetricAlgorithmSecurityHeader sech;
	srl.unserialize(sctx, sech);

	SequenceHeader seqh;
	srl.unserialize(sctx, seqh);

	OpenSecureChannelResponse resp;
	NodeId resp_id;

	srl.unserialize(sctx, resp_id);
	if (resp_id.type != NodeIdType::NUMERIC || resp_id.id.as_int != id_mapping.at(resp.node_id()))
		throw std::runtime_error("Unknown response for OPN");

	srl.unserialize(sctx, resp);

	// was this our request?
	if (seqh.request_id == channel_request_id)
	{
		secure_channel_id = channel_id;
		token_id = resp.security_token.token_id;
		on_connected();
		return true;
	}
	else
		return false;
}

void opc_ua::tcp::MessageStream::close()
{
	TemporarySerializationContext sctx;
	BinarySerializer srl;

	SymmetricAlgorithmSecurityHeader sech = {
		.token_id = token_id,
	};
	srl.serialize(sctx, sech);

	SequenceHeader seqh = {
		.sequence_number = sequence_number++,
		.request_id = next_request_id++,
	};
	srl.serialize(sctx, seqh);

	CloseSecureChannelRequest req(seqh.request_id);
	NodeId req_id(id_mapping.at(req.node_id()));

	srl.serialize(sctx, req_id);
	srl.serialize(sctx, req);

	srl.serialize(sctx, Byte(0));

	ts.write_message(MessageType::CLO, MessageIsFinal::FINAL, sctx, secure_channel_id);
}
