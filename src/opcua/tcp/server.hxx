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
		extern const UInt32 server_namespace_index;

		// (opaque)
		class Server;
		class ServerTransportStream;
		class ServerSessionStream;

		class ServerMessageStream
		{
			Server& server;
			ServerTransportStream& ts;
			ServerSessionStream* attached_session;

			// sequential number source
			static UInt32 sequence_number;
			static UInt32 next_request_id;

			// secure channel id for write_message()
			UInt32 secure_channel_id;
			// security token id for further messages
			UInt32 token_id;

			// segmented message support
			std::unordered_map<UInt32, MemorySerializationBuffer> chunk_store;

		public:
			ServerMessageStream(Server& serv, ServerTransportStream& new_ts);
			~ServerMessageStream();

			// fill in the response header and send the message through
			// the associated secure channel.
			void write_message(Response& msg, UInt32 request_id, MessageType msg_type = MessageType::MSG);

			// process secure channel response
			// return true if it matches our request
			void process_secure_channel_request(ReadableSerializationBuffer& buf, UInt32 channel_id);
			// handle incoming message.
			void handle_message(MessageHeader& h, ReadableSerializationBuffer& chunk);
		};

		class ServerTransportStream
		{
			Server& server;
			bufferevent* bev;
			ReadableSerializationBuffer in_ctx;
			WritableSerializationBuffer out_ctx;

			// current state
			bool connected;
			bool got_header;
			MessageHeader h;

			// remote side limits
			ProtocolInfo remote_limits;

			// secure channels
			std::unordered_map<UInt32, ServerMessageStream> secure_channels;
			static UInt32 next_secure_channel_id;

			static void read_handler(bufferevent* bev, void* ctx);
			static void event_handler(bufferevent* bev, short what, void* ctx);

		public:
			ServerTransportStream(Server& serv, event_base* ev, evutil_socket_t sock);
			~ServerTransportStream();

			void write_message(MessageType msg_type, MessageIsFinal is_final, ReadableSerializationBuffer& msg, UInt32 secure_channel_id = 0);
		};

		class ServerSessionStream
		{
			ServerMessageStream* secure_channel;

			std::string session_name;

#if 0
			// internal callbacks
			static void handle_create_session(std::unique_ptr<Response> msg, void* data);
			static void handle_activate_session(std::unique_ptr<Response> msg, void* data);
#endif

		public:
			// session info
			NodeId session_id;
			NodeId authentication_token;

			ServerSessionStream(const CreateSessionRequest& csr, CreateSessionResponse& resp);

			void attach(ServerMessageStream& ms, const ActivateSessionRequest& asr, UInt32 request_id);

			void write_message(Response& msg, UInt32 request_id);
		};

		class Server
		{
			evconnlistener* listener;

			static void handle_connection(evconnlistener* listener,
					evutil_socket_t sock, sockaddr* addr, int socklen, void* data);

			std::vector<ServerTransportStream> connections;
			std::vector<ServerSessionStream> sessions;

		public:
			Server(event_base* ev);

			CreateSessionResponse create_session(const CreateSessionRequest& csr);
			ServerSessionStream& activate_session(const ActivateSessionRequest& asr, ServerMessageStream& ms, UInt32 request_id);
		};
	};
};

#endif /*OPCUA_TCP_SERVER_HXX*/
