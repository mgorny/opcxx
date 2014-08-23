/* OPC UA protocol implementation
 * (c) 2014 Michał Górny
 * Licensed under the terms of the 2-clause BSD license
 */

#pragma once

#ifndef OPCUA_TCP_SERVER_HXX
#define OPCUA_TCP_SERVER_HXX 1

#include <event2/bufferevent.h>
#include <event2/event.h>
#include <event2/listener.h>

#include <opcua/common/struct.hxx>
#include <opcua/common/types.hxx>
#include <opcua/common/util.hxx>
#include <opcua/tcp/types.hxx>

#include <vector>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>

namespace opc_ua
{
	namespace tcp
	{
		class ServerTransportStream
		{
			bufferevent* bev;
			ReadableSerializationBuffer in_ctx;
			WritableSerializationBuffer out_ctx;

			// current state
			bool connected;
			bool got_header;
			MessageHeader h;

			// remote side limits
			HelloMessage remote_limits;

			// secure channels
//			std::unordered_map<UInt32, MessageStream*> secure_channels;

			static void read_handler(bufferevent* bev, void* ctx);
			static void event_handler(bufferevent* bev, short what, void* ctx);

		public:
			ServerTransportStream(event_base* ev, evutil_socket_t sock);
			~ServerTransportStream();

			void write_message(MessageType msg_type, MessageIsFinal is_final, ReadableSerializationBuffer& msg, UInt32 secure_channel_id = 0);
		};
#if 0

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

			// segmented message support
			std::unordered_map<UInt32, MemorySerializationBuffer> chunk_store;

		public:
			MessageStream(TransportStream& new_ts);
			~MessageStream();

			// fill in the request header and send the message through
			// the associated secure channel.
			void write_message(Request& msg, MessageType msg_type = MessageType::MSG);

			// write secure channel request
			void request_secure_channel();
			// process secure channel response
			// return true if it matches our request
			bool process_secure_channel_response(ReadableSerializationBuffer& buf, UInt32 channel_id);
			// request closing secure channel
			void close();
			// handle incoming message.
			void handle_message(MessageHeader& h, ReadableSerializationBuffer& chunk);

			// Attach a new session stream.
			void attach_session(SessionStream& s);
		};

		// Wrapper that establishes a session over MessageStream. Supports
		// reattaching to a different TransportStream and resuming session.
		class SessionStream
		{
		public:
			typedef std::function<void(std::unique_ptr<Response>, void*)>
				request_callback_type;

		private:
			MessageStream* secure_channel;

			std::string session_name;
			// endpoint URI for session create request
			std::string endpoint_uri;

			bool session_established;

			// session info
			NodeId session_id;
			NodeId authentication_token;

			// request map
			struct callback_data
			{
				request_callback_type callback;
				void* data;
			};
			std::unordered_map<UInt32, callback_data> callbacks;

			// callback for session start
			callback_data session_established_callback;

			// internal callbacks
			static void handle_create_session(std::unique_ptr<Response> msg, void* data);
			static void handle_activate_session(std::unique_ptr<Response> msg, void* data);

		public:
			SessionStream(const std::string& sess_name);

			// Send request and register the callback for response.
			void write_message(Request& msg, request_callback_type callback, void* cb_data);

			// Attach to a secure channel.
			void attach(MessageStream& ms, const std::string& endpoint, request_callback_type on_established = {}, void* cb_data = nullptr);
			// Start/resume session.
			void open_session();
			// Handle incoming message.
			void on_message(std::unique_ptr<Response> msg);
		};
#endif

		class Server
		{
			event_base* ev_base;
			evconnlistener* listener;

			static void handle_connection(evconnlistener* listener,
					evutil_socket_t sock, sockaddr* addr, int socklen, void* data);

			std::vector<ServerTransportStream> connections;

		public:
			Server(event_base* ev);
		};
	};
};

#endif /*OPCUA_TCP_SERVER_HXX*/
