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

void opc_ua::tcp::TransportStream::connect_hostname(const char* hostname, uint16_t port, const std::string& endpoint, sa_family_t family)
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

	MemorySerializationBuffer sctx;
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

	MemorySerializationBuffer buf;
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
				MemorySerializationBuffer copy_buf;
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
		{
			UInt32 secure_channel_id;
			srl.unserialize(buf, secure_channel_id);

			s->secure_channels[secure_channel_id]->handle_message(s->h, buf);
			break;
		}

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

void opc_ua::tcp::TransportStream::write_message(MessageType msg_type, MessageIsFinal is_final, ReadableSerializationBuffer& msg, UInt32 channel_id)
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

	out_ctx.move(msg);
}

void opc_ua::tcp::TransportStream::add_secure_channel(MessageStream& ms)
{
	secure_channel_queue.push_back(&ms);
	if (connected)
		ms.request_secure_channel();
}

opc_ua::tcp::MessageStream::MessageStream(TransportStream& new_ts)
	: ts(new_ts), attached_session(nullptr), established(false)
{
	ts.add_secure_channel(*this);
}

opc_ua::tcp::MessageStream::~MessageStream()
{
}

void opc_ua::tcp::MessageStream::write_message(Request& msg, MessageType msg_type)
{
	MemorySerializationBuffer sctx;
	BinarySerializer srl;

	// OPN message takes asymmetric header
	// MSG & CLO take symmetric header
	if (msg_type == MessageType::OPN)
	{
		AsymmetricAlgorithmSecurityHeader sech = {
			.security_policy_uri = "http://opcfoundation.org/UA/SecurityPolicy#None",
			.sender_certificate = "",
			.receiver_certificate_thumbprint = "",
		};
		srl.serialize(sctx, sech);
	}
	else
	{
		SymmetricAlgorithmSecurityHeader sech = {
			.token_id = token_id,
		};
		srl.serialize(sctx, sech);
	}

	SequenceHeader seqh = {
		.sequence_number = sequence_number++,
		.request_id = next_request_id++,
	};
	srl.serialize(sctx, seqh);

	NodeId msg_id(id_mapping.at(msg.get_node_id()));
	srl.serialize(sctx, msg_id);

	// fill request header in
	msg.request_header.timestamp = DateTime::now();
	msg.request_header.request_handle = seqh.request_id;
	srl.serialize(sctx, msg);

	ts.write_message(msg_type, MessageIsFinal::FINAL, sctx, secure_channel_id);
}

void opc_ua::tcp::MessageStream::request_secure_channel()
{
	channel_request_id = sequence_number;

	OpenSecureChannelRequest req(SecurityTokenRequestType::ISSUE,
			MessageSecurityMode::NONE, "", 360000);

	write_message(req, MessageType::OPN);
}

bool opc_ua::tcp::MessageStream::process_secure_channel_response(ReadableSerializationBuffer& sctx, UInt32 channel_id)
{
	BinarySerializer srl;
	AsymmetricAlgorithmSecurityHeader sech;
	srl.unserialize(sctx, sech);

	SequenceHeader seqh;
	srl.unserialize(sctx, seqh);

	OpenSecureChannelResponse resp;
	NodeId resp_id;

	srl.unserialize(sctx, resp_id);
	if (resp_id.type != NodeIdType::NUMERIC || resp_id.as_int != id_mapping.at(resp.get_node_id()))
		throw std::runtime_error("Unknown response for OPN");

	srl.unserialize(sctx, resp);

	// was this our request?
	if (seqh.request_id == channel_request_id)
	{
		secure_channel_id = channel_id;
		assert(secure_channel_id == resp.security_token.channel_id);
		token_id = resp.security_token.token_id;
		established = true;
		if (attached_session)
			attached_session->open_session();
		return true;
	}
	else
		return false;
}

void opc_ua::tcp::MessageStream::close()
{
	CloseSecureChannelRequest req;

	write_message(req, MessageType::CLO);
}

void opc_ua::tcp::MessageStream::handle_message(MessageHeader& h, ReadableSerializationBuffer& chunk)
{
	BinarySerializer srl;
	SymmetricAlgorithmSecurityHeader sech;
	srl.unserialize(chunk, sech);

	if (sech.token_id != token_id)
		throw std::runtime_error("Incorrect token ID received");

	SequenceHeader seqh;
	srl.unserialize(chunk, seqh);

	MemorySerializationBuffer body;

	switch (h.is_final)
	{
		case MessageIsFinal::INTERMEDIATE:
			chunk_store[seqh.request_id].move(chunk);
			return;
		case MessageIsFinal::ABORTED:
		{
			UInt32 error;
			String reason;

			srl.unserialize(chunk, error);
			srl.unserialize(chunk, reason);
			// TODO: report the error

			chunk_store.erase(seqh.request_id);
			return;
		}
		case MessageIsFinal::FINAL:
		{
			auto it = chunk_store.find(seqh.request_id);

			if (it != chunk_store.end())
			{
				body.move((*it).second);
				chunk_store.erase(it);
			}

			body.move(chunk);
			break;
		}
		default:
			throw std::runtime_error("Invalid IsFinal value");
	}

	NodeId msg_id;
	srl.unserialize(body, msg_id);

	if (msg_id.type != NodeIdType::NUMERIC)
		throw std::runtime_error("Non-numeric node id received");
	if (msg_id.ns != 0)
		throw std::runtime_error("Non-standard namespace received");

	UInt32 base_id = reverse_id_mapping.at(msg_id.as_int);
	Struct* msg = struct_constructors.at(base_id)();
	msg->unserialize(body, srl);

	// convert to Response
	// XXX: check type properly
	std::unique_ptr<Response> resp(dynamic_cast<Response*>(msg));

	if (body.size() != 0)
		throw std::runtime_error("Part of message body not unserialized");

	switch (h.message_type)
	{
		case MessageType::MSG:
			if (attached_session)
				attached_session->on_message(std::move(resp));
			else
				throw std::runtime_error("Got message with no session!");
			break;
		// TODO: handle CLO
		default:
			assert(not_reached);
	}
}

void opc_ua::tcp::MessageStream::attach_session(SessionStream& s)
{
	attached_session = &s;

	if (established)
		s.open_session();
}

void opc_ua::tcp::SessionStream::handle_create_session(std::unique_ptr<Response> msg, void* data)
{
	SessionStream* self = static_cast<SessionStream*>(data);
	CreateSessionResponse* resp = dynamic_cast<CreateSessionResponse*>(msg.get());

	self->session_id = resp->session_id;
	self->authentication_token = resp->authentication_token;

	opc_ua::ActivateSessionRequest asr;
	asr.user_identity_token.inner_object.reset(new opc_ua::AnonymousIdentityToken);
	asr.locale_ids.emplace_back("en");

	self->write_message(asr, self->handle_activate_session, data);
}

void opc_ua::tcp::SessionStream::handle_activate_session(std::unique_ptr<Response> msg, void* data)
{
	SessionStream* self = static_cast<SessionStream*>(data);
	ActivateSessionResponse* resp = dynamic_cast<ActivateSessionResponse*>(msg.get());

	if (resp->results.at(0) != 0)
		throw std::runtime_error("Activate session request failed");
	self->session_established = true;

	self->session_established_callback.callback(std::move(msg),
			self->session_established_callback.data);
}

opc_ua::tcp::SessionStream::SessionStream(const std::string& sess_name)
	: secure_channel(nullptr), session_name(sess_name),
	session_established(false)
{
}

void opc_ua::tcp::SessionStream::write_message(Request& msg, request_callback_type callback, void* cb_data)
{
	msg.request_header.authentication_token = authentication_token;

	secure_channel->write_message(msg);
	callbacks[msg.request_header.request_handle] = {
		.callback = callback,
		.data = cb_data
	};
}

void opc_ua::tcp::SessionStream::attach(MessageStream& ms, const std::string& endpoint, request_callback_type on_established, void* cb_data)
{
	secure_channel = &ms;
	endpoint_uri = endpoint;
	ms.attach_session(*this);

	session_established_callback.callback = on_established;
	session_established_callback.data = cb_data;
}

void opc_ua::tcp::SessionStream::open_session()
{
	opc_ua::CreateSessionRequest csr(
		opc_ua::ApplicationType::CLIENT,
		endpoint_uri,
		session_name,
		random_nonce(),
		1E9);

	write_message(csr, handle_create_session, this);
}

void opc_ua::tcp::SessionStream::on_message(std::unique_ptr<Response> msg)
{
	auto it = callbacks.find(msg->response_header.request_handle);

	if (it == callbacks.end())
		throw std::runtime_error("Got a response to unknown request");

	it->second.callback(std::move(msg), it->second.data);

	callbacks.erase(it);
}
