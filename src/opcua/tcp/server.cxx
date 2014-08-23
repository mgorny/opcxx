/* OPC UA protocol implementation
 * (c) 2014 Michał Górny
 * Licensed under the terms of the 2-clause BSD license
 */

#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif

#include "server.hxx"

#include <cassert>

opc_ua::tcp::ServerTransportStream::ServerTransportStream(event_base* ev, evutil_socket_t sock)
	: bev(bufferevent_socket_new(ev, sock, BEV_OPT_CLOSE_ON_FREE)),
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

	self->connections.emplace_back(self->ev_base, sock);
}

opc_ua::tcp::Server::Server(event_base* ev)
{
	sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(6001),
		.sin_addr = {INADDR_ANY},
	};

	listener = evconnlistener_new_bind(ev,
			handle_connection, this,
			LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1,
			reinterpret_cast<sockaddr*>(&addr), sizeof(addr));

	assert(listener);
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
			srl.unserialize(buf, s->remote_limits);

			AcknowledgeMessage ack;

			s->connected = true;
			break;
		}

		case MessageType::ERR:
		{
			ErrorMessage err;
			srl.unserialize(buf, err);

			throw std::runtime_error("ERR message received");
			break;
		}

#if 0
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
#endif

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

