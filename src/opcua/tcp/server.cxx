/* OPC UA protocol implementation
 * (c) 2014 Michał Górny
 * Licensed under the terms of the 2-clause BSD license
 */

#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif

#include "server.hxx"

#include <opcua/tcp/idmapping.hxx>

#include <cassert>
#include <random>

// TODO?
const opc_ua::UInt32 opc_ua::tcp::server_namespace_index = 1;

opc_ua::UInt32 opc_ua::tcp::ServerMessageStream::sequence_number = 0;
opc_ua::UInt32 opc_ua::tcp::ServerMessageStream::next_request_id = 0;
opc_ua::UInt32 opc_ua::tcp::ServerTransportStream::next_secure_channel_id = 1;

opc_ua::tcp::ServerTransportStream::ServerTransportStream(Server& serv, event_base* ev, evutil_socket_t sock)
	: server(serv),
	bev(bufferevent_socket_new(ev, sock, BEV_OPT_CLOSE_ON_FREE)),
	in_ctx(bufferevent_get_input(bev)),
	out_ctx(bufferevent_get_output(bev)),
	connected(false), got_header(false)
{
	assert(bev);

	bufferevent_setcb(bev, read_handler, 0, event_handler, this);
	bufferevent_enable(bev, EV_READ);
}

opc_ua::tcp::ServerTransportStream::~ServerTransportStream()
{
	bufferevent_free(bev);
}

void opc_ua::tcp::Server::handle_connection(evconnlistener* listener,
					evutil_socket_t sock, sockaddr* addr, int socklen, void* data)
{
	Server* self = static_cast<Server*>(data);

	self->connections.emplace_back(*self, evconnlistener_get_base(self->listener), sock);
}

opc_ua::tcp::Server::Server(event_base* ev, AddressSpace& as)
	: address_space(as)
{
	sockaddr_in addr = sockaddr_in();

	addr.sin_family = AF_INET;
	addr.sin_port = htons(6001);
	addr.sin_addr = {INADDR_ANY};

	listener = evconnlistener_new_bind(ev,
			handle_connection, this,
			LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1,
			reinterpret_cast<sockaddr*>(&addr), sizeof(addr));

	assert(listener);
}

opc_ua::CreateSessionResponse opc_ua::tcp::Server::create_session(const CreateSessionRequest& csr)
{
	CreateSessionResponse resp;
	sessions.emplace_back(*this, csr, resp);
	return resp;
}

opc_ua::tcp::ServerSessionStream& opc_ua::tcp::Server::activate_session(const ActivateSessionRequest& asr, ServerMessageStream& ms, UInt32 request_id)
{
	for (auto& s : sessions)
	{
		// TODO: we should actually match using signatures...
		if (asr.request_header.authentication_token == s.authentication_token)
		{
			s.attach(ms, asr, request_id);
			return s;
		}
	}

	throw std::runtime_error("Attempt to activate non-existing session");
}

void opc_ua::tcp::ServerTransportStream::read_handler(bufferevent* bev, void* ctx)
{
	BinarySerializer srl;
	ServerTransportStream* s = static_cast<ServerTransportStream*>(ctx);

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
		case MessageType::HEL:
		{
			HelloMessage hel;
			srl.unserialize(buf, hel);
			s->remote_limits = hel.protocol_info;

			MemorySerializationBuffer out_buf;
			AcknowledgeMessage ack;
			ack.protocol_info = libevent_protocol_info;
			srl.serialize(out_buf, ack);
			s->write_message(MessageType::ACK, MessageIsFinal::FINAL, out_buf);

			s->connected = true;
			break;
		}

		// XXX: can client send it?
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

			secure_channel_id = next_secure_channel_id++;
			s->secure_channels.emplace(secure_channel_id,
					std::move(ServerMessageStream{s->server, *s}));
			s->secure_channels.at(secure_channel_id).process_secure_channel_request(buf, secure_channel_id);
			break;
		}

		case MessageType::CLO:
		case MessageType::MSG:
		{
			UInt32 secure_channel_id;
			srl.unserialize(buf, secure_channel_id);

			s->secure_channels.at(secure_channel_id).handle_message(s->h, buf);
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

void opc_ua::tcp::ServerTransportStream::event_handler(bufferevent* bev, short what, void* ctx)
{
	if (what & BEV_EVENT_EOF)
		throw std::runtime_error("Server transport stream disconnected");
	if (what & BEV_EVENT_ERROR)
		throw std::runtime_error("Server transport stream error");
}

void opc_ua::tcp::ServerTransportStream::write_message(MessageType msg_type, MessageIsFinal is_final, ReadableSerializationBuffer& msg, UInt32 channel_id)
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

opc_ua::tcp::ServerMessageStream::ServerMessageStream(Server& serv, ServerTransportStream& new_ts)
	: server(serv), ts(new_ts), attached_session(nullptr)
{
}

opc_ua::tcp::ServerMessageStream::~ServerMessageStream()
{
}

void opc_ua::tcp::ServerMessageStream::write_message(Response& msg, UInt32 request_id, MessageType msg_type)
{
	MemorySerializationBuffer headers, body;
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
		srl.serialize(headers, sech);
	}
	else
	{
		SymmetricAlgorithmSecurityHeader sech = {
			.token_id = token_id,
		};
		srl.serialize(headers, sech);
	}

	SequenceHeader seqh = {
		.sequence_number = sequence_number++,
		.request_id = request_id,
	};

	NodeId msg_id(id_mapping.at(msg.get_node_id()));
	srl.serialize(body, msg_id);

	// fill response header in
	msg.response_header.timestamp = DateTime::now();
	srl.serialize(body, msg);

	// message splitting support
	size_t max_chunk_size = ts.remote_limits.receive_buffer_size
		- SecureConversationMessageHeader::serialized_length
		- SequenceHeader::serialized_length
		- headers.size();

	std::vector<Byte> headers_copy(headers.size());
	headers.read(headers_copy.data(), headers_copy.size());

	while (1)
	{
		MemorySerializationBuffer buf;

		buf.write(headers_copy.data(), headers_copy.size());
		srl.serialize(buf, seqh);
		buf.move(body, max_chunk_size);

		ts.write_message(msg_type,
				body.size() > 0 ? MessageIsFinal::INTERMEDIATE : MessageIsFinal::FINAL,
				buf, secure_channel_id);

		if (body.size() == 0)
			break;

		seqh.sequence_number = sequence_number++;
	}
}

void opc_ua::tcp::ServerMessageStream::process_secure_channel_request(ReadableSerializationBuffer& sctx, UInt32 channel_id)
{
	BinarySerializer srl;
	AsymmetricAlgorithmSecurityHeader sech;
	srl.unserialize(sctx, sech);

	SequenceHeader seqh;
	srl.unserialize(sctx, seqh);

	OpenSecureChannelRequest req;
	NodeId req_id;

	srl.unserialize(sctx, req_id);
	if (req_id.type != NodeIdType::NUMERIC || req_id.as_int != id_mapping.at(req.get_node_id()))
		throw std::runtime_error("Unknown request for OPN");

	srl.unserialize(sctx, req);

	if (req.security_mode != MessageSecurityMode::NONE)
		throw std::runtime_error("Security mode unsupported");

	std::random_device rnd("/dev/random");
	std::uniform_int_distribution<opc_ua::UInt32> dist;

	secure_channel_id = channel_id;
	token_id = dist(rnd);

	OpenSecureChannelResponse resp;
	resp.response_header.request_handle = req.request_header.request_handle;
	resp.response_header.service_result = 0;
	resp.security_token.created_at = DateTime::now();
	resp.security_token.channel_id = secure_channel_id;
	resp.security_token.token_id = token_id;

	resp.server_protocol_version = 0;

	write_message(resp, seqh.request_id, MessageType::OPN);
}

void opc_ua::tcp::ServerMessageStream::handle_message(MessageHeader& h, ReadableSerializationBuffer& chunk)
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

	// convert to Request
	// XXX: check type properly
	std::unique_ptr<Request> req(dynamic_cast<Request*>(msg));

	if (body.size() != 0)
		throw std::runtime_error("Part of message body not unserialized");

	switch (h.message_type)
	{
		case MessageType::MSG:
		{
			switch (req->get_node_id())
			{
				case CreateSessionRequest::NODE_ID:
				{
					const CreateSessionRequest& csr
						= *dynamic_cast<CreateSessionRequest*>(req.get());

					CreateSessionResponse resp = server.create_session(csr);
					write_message(resp, seqh.request_id);

					break;
				}

				case ActivateSessionRequest::NODE_ID:
				{
					const ActivateSessionRequest& asr
						= *dynamic_cast<ActivateSessionRequest*>(req.get());

					attached_session = &server.activate_session(asr, *this, seqh.request_id);
					break;
				}

				// TODO: move to ServerSessionStream
				case ReadRequest::NODE_ID:
				{
					const ReadRequest& rr = *dynamic_cast<ReadRequest*>(req.get());
					ReadResponse resp;

					resp.response_header.request_handle = rr.request_header.request_handle;
					resp.response_header.service_result = 0;
					resp.results.resize(rr.nodes_to_read.size());

					for (auto& r : rr.nodes_to_read)
					{
						BaseNode& n = server.address_space.get_node(r.node_id);
						// TODO: index_range, data_encoding

						resp.results[0].flags = static_cast<Byte>(DataValueFlags::VALUE_SPECIFIED);
						resp.results[0].value = n.get_attribute(static_cast<AttributeId>(r.attribute_id),
									attached_session->session);
					}

					write_message(resp, seqh.request_id);
					break;
				}

				default:
					assert(not_reached);
			}

			break;
		}
		// TODO: handle CLO
		default:
			assert(not_reached);
	}
}

opc_ua::tcp::ServerSessionStream::ServerSessionStream(Server& serv, const CreateSessionRequest& csr, CreateSessionResponse& resp)
	: server(serv), secure_channel(nullptr), session_name(csr.session_name),
	session_id(GUID::random_guid(), server_namespace_index),
	authentication_token(GUID::random_guid(), server_namespace_index)
{
	resp.response_header.request_handle = csr.request_header.request_handle;
	resp.response_header.service_result = 0;

	resp.session_id = session_id;
	resp.authentication_token = authentication_token;
	resp.server_nonce = random_nonce();
}

void opc_ua::tcp::ServerSessionStream::attach(ServerMessageStream& ms, const ActivateSessionRequest& asr, UInt32 request_id)
{
	secure_channel = &ms;

	ActivateSessionResponse resp;

	resp.response_header.request_handle = asr.request_header.request_handle;
	resp.response_header.service_result = 0;

	resp.server_nonce = random_nonce();
	resp.results.push_back(0);

	write_message(resp, request_id);
}

void opc_ua::tcp::ServerSessionStream::write_message(Response& msg, UInt32 request_id)
{
	secure_channel->write_message(msg, request_id);
}

void opc_ua::AddressSpace::add_node(const std::shared_ptr<BaseNode>& n)
{
	nodes.emplace(n.get()->node_id(), n);
}

opc_ua::BaseNode& opc_ua::AddressSpace::get_node(const NodeId& n)
{
	return *nodes.at(n).get();
}
