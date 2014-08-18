/* OPC UA protocol implementation
 * (c) 2014 Michał Górny
 * Licensed under the terms of the 2-clause BSD license
 */

#pragma once

#ifndef OPCUA_TCP_STREAMS_HXX
#define OPCUA_TCP_STREAMS_HXX 1

#include <event2/bufferevent.h>
#include <event2/event.h>

#include <opcua/common/struct.hxx>
#include <opcua/common/types.hxx>
#include <opcua/common/util.hxx>
#include <opcua/tcp/types.hxx>

#include <memory>
#include <unordered_map>
#include <vector>

#include <sys/socket.h>

namespace opc_ua
{
	namespace tcp
	{
		// (opaque)
		class MessageStream;
		class SessionStream;

		// Basic OPC UA TCP transport stream. Handles connecting and message
		// headers.
		class TransportStream
		{
			bufferevent* bev;
			SerializationContext in_ctx, out_ctx;

			// current state
			bool connected;
			bool got_header;
			MessageHeader h;

			// remote side limits
			AcknowledgeMessage remote_limits;

			// secure channels
			std::unordered_map<UInt32, MessageStream*> secure_channels;
			std::vector<MessageStream*> secure_channel_queue;

			static void read_handler(bufferevent* bev, void* ctx);
			static void event_handler(bufferevent* bev, short what, void* ctx);

		public:
			TransportStream(event_base* ev);
			~TransportStream();

			void connect_hostname(const char* hostname, uint16_t port, const std::string& endpoint, sa_family_t family = AF_UNSPEC);
			void write_message(MessageType msg_type, MessageIsFinal is_final, SerializationContext& msg, UInt32 secure_channel_id = 0);

			// Queue a request for secure channel.
			void add_secure_channel(MessageStream& ms);
		};

		// Wrapper stream that splits, encodes and transmits OPC messages.
		class MessageStream
		{
			TransportStream& ts;
			SessionStream* attached_session;

			// sequential number source
			static UInt32 sequence_number;
			static UInt32 next_request_id;

			// Is the channel established already?
			bool established;
			// OPN request identifier
			UInt32 channel_request_id;
			// secure channel id for write_message()
			UInt32 secure_channel_id;
			// security token id for further messages
			UInt32 token_id;

		public:
			MessageStream(TransportStream& new_ts);
			~MessageStream();

			void write_message(Request& msg, MessageType msg_type = MessageType::MSG);

			// write secure channel request
			void request_secure_channel();
			// process secure channel response
			// return true if it matches our request
			bool process_secure_channel_response(SerializationContext& buf, UInt32 channel_id);
			// request closing secure channel
			void close();
			// handle incoming message.
			void handle_message(MessageHeader& h, SerializationContext& body);

			// Attach a new session stream.
			void attach_session(SessionStream& s);
		};

		// Wrapper that establishes a session over MessageStream. Supports
		// reattaching to a different TransportStream and resuming session.
		class SessionStream
		{
			MessageStream* secure_channel;

			std::string session_name;
			// endpoint URI for session create request
			std::string endpoint_uri;

			bool session_established;

			// session info
			NodeId session_id;
			NodeId authentication_token;

		public:
			SessionStream(const std::string& sess_name);

			// Attach to a secure channel.
			void attach(MessageStream& ms, const std::string& endpoint);
			// Start/resume session.
			void open_session();
			// Handle incoming message.
			void on_message(std::unique_ptr<Response> msg);
		};
	};
};

#endif /*OPCUA_TCP_STREAMS_HXX*/
