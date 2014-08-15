/* OPC UA protocol implementation
 * (c) 2014 Michał Górny
 * Licensed under the terms of the 2-clause BSD license
 */

#pragma once

#ifndef TCP_HXX
#define TCP_HXX 1

#include <event2/bufferevent.h>
#include <event2/event.h>

#include <opcua/struct.hxx>
#include <opcua/types.hxx>
#include <opcua/util.hxx>

#include <exception>
#include <functional>

#include <sys/socket.h>

namespace opc_ua
{
	namespace tcp
	{
		enum class BinaryNodeIdType
		{
			TWO_BYTE = 0,
			FOUR_BYTE = 1,
			NUMERIC = 2,
			STRING = 3,
			GUID = 4,
			BYTE_STRING = 5,
		};

		// special types
		namespace message_type_const
		{
			// message type strings
			constexpr uint8_t HEL[] = "HEL";
			constexpr uint8_t ACK[] = "ACK";
			constexpr uint8_t ERR[] = "ERR";
			constexpr uint8_t MSG[] = "MSG";
			constexpr uint8_t OPN[] = "OPN";
			constexpr uint8_t CLO[] = "CLO";

			// convert into useful little-endian integers
			constexpr uint32_t as_uint(const uint8_t sv[4])
			{
				return sv[2] << 16 | sv[1] << 8 | sv[0];
			}
		};

		enum class MessageType
		{
			// initial messages
			HEL = message_type_const::as_uint(message_type_const::HEL),
			ACK = message_type_const::as_uint(message_type_const::ACK),
			ERR = message_type_const::as_uint(message_type_const::ERR),

			// secure conversation messages
			MSG = message_type_const::as_uint(message_type_const::MSG),
			OPN = message_type_const::as_uint(message_type_const::OPN),
			CLO = message_type_const::as_uint(message_type_const::CLO),
		};

		enum class MessageIsFinal
		{
			INTERMEDIATE = 'C',
			FINAL = 'F',
			ABORTED = 'A',
		};

		// protocol messages
		struct MessageHeader
		{
			MessageType message_type;
			MessageIsFinal is_final;
			UInt32 message_size;

			static constexpr size_t serialized_length
				= sizeof(opc_ua::Byte)*4
				+ sizeof(message_size);
		};

		struct SecureConversationMessageHeader : public MessageHeader
		{
			UInt32 secure_channel_id;

			static constexpr size_t serialized_length
				= sizeof(opc_ua::Byte)*4
				+ sizeof(message_size)
				+ sizeof(secure_channel_id);
		};

		struct HelloMessage
		{
			UInt32 protocol_version;
			UInt32 receive_buffer_size;
			UInt32 send_buffer_size;
			UInt32 max_message_size;
			UInt32 max_chunk_count;
			String endpoint_url;
		};

		struct AcknowledgeMessage
		{
			UInt32 protocol_version;
			UInt32 receive_buffer_size;
			UInt32 send_buffer_size;
			UInt32 max_message_size;
			UInt32 max_chunk_count;
		};

		struct ErrorMessage
		{
			UInt32 error;
			String reason;
		};

		struct AsymmetricAlgorithmSecurityHeader
		{
			String security_policy_uri;
			String sender_certificate;
			String receiver_certificate_thumbprint;
		};

		struct SymmetricAlgorithmSecurityHeader
		{
			UInt32 token_id;
		};

		struct SequenceHeader
		{
			UInt32 sequence_number;
			UInt32 request_id;
		};

		struct SecureConversationMessageFooter
		{
			Byte padding_size;

			// (present only when encrypted)
			// Byte padding[];
			// Byte signature[];
		};

		struct BinarySerializer : public Serializer
		{
			virtual void serialize(SerializationContext& ctx, Byte i);
			virtual void serialize(SerializationContext& ctx, UInt16 i);
			virtual void serialize(SerializationContext& ctx, UInt32 i);
			virtual void serialize(SerializationContext& ctx, Int32 i);
			virtual void serialize(SerializationContext& ctx, Int64 i);
			virtual void serialize(SerializationContext& ctx, String s);
			virtual void serialize(SerializationContext& ctx, DateTime t);
			virtual void serialize(SerializationContext& ctx, NodeId n);
			virtual void serialize(SerializationContext& ctx, Struct& s);
			virtual void serialize(SerializationContext& ctx, Array<String>& a);
			virtual void serialize(SerializationContext& ctx, ExtensionObject& s);

			virtual void unserialize(SerializationContext& ctx, Byte& i);
			virtual void unserialize(SerializationContext& ctx, UInt16& i);
			virtual void unserialize(SerializationContext& ctx, Int32& i);
			virtual void unserialize(SerializationContext& ctx, UInt32& i);
			virtual void unserialize(SerializationContext& ctx, Int64& i);
			virtual void unserialize(SerializationContext& ctx, String& s);
			virtual void unserialize(SerializationContext& ctx, DateTime& t);
			virtual void unserialize(SerializationContext& ctx, NodeId& n);
			virtual void unserialize(SerializationContext& ctx, Struct& s);
			virtual void unserialize(SerializationContext& ctx, Array<String>& a);
			virtual void unserialize(SerializationContext& ctx, ExtensionObject& s);

			// UA TCP specific types
			void serialize(SerializationContext& ctx, MessageIsFinal b);
			void serialize(SerializationContext& ctx, MessageType t);
			void serialize(SerializationContext& ctx, const MessageHeader& h);
			void serialize(SerializationContext& ctx, const SecureConversationMessageHeader& h);
			void serialize(SerializationContext& ctx, const HelloMessage& msg);
			void serialize(SerializationContext& ctx, const AcknowledgeMessage& msg);
			void serialize(SerializationContext& ctx, const ErrorMessage& msg);
			void serialize(SerializationContext& ctx, const AsymmetricAlgorithmSecurityHeader& h);
			void serialize(SerializationContext& ctx, const SequenceHeader& h);

			void unserialize(SerializationContext& ctx, MessageIsFinal& b);
			void unserialize(SerializationContext& ctx, MessageType& t);
			void unserialize(SerializationContext& ctx, MessageHeader& h);
			void unserialize(SerializationContext& ctx, HelloMessage& msg);
			void unserialize(SerializationContext& ctx, AcknowledgeMessage& msg);
			void unserialize(SerializationContext& ctx, ErrorMessage& msg);
			void unserialize(SerializationContext& ctx, AsymmetricAlgorithmSecurityHeader& h);
			void unserialize(SerializationContext& ctx, SequenceHeader& h);
		};

		// Basic OPC UA TCP transport stream. Handles connecting and message
		// headers.
		class TransportStream
		{
		public:
			typedef std::function<void(void* data)> ack_callback_type;
			typedef std::function<void(const MessageHeader& h, SerializationContext& ctx, void* data)> msg_callback_type;

		private:
			bufferevent* bev;
			SerializationContext in_ctx, out_ctx;

			// current state
			bool got_header;
			MessageHeader h;

			// remote side limits
			AcknowledgeMessage remote_limits;

			// callbacks
			ack_callback_type ack_callback;
			msg_callback_type msg_callback;
			void* callback_data;

			static void read_handler(bufferevent* bev, void* ctx);

		public:
			TransportStream(event_base* ev);
			~TransportStream();

			void connect_hostname(const char* hostname, uint16_t port, const char* endpoint, sa_family_t family = AF_UNSPEC);
			void write_message(MessageType msg_type, MessageIsFinal is_final, SerializationContext& msg);

			void set_callbacks(ack_callback_type ack_cb, msg_callback_type msg_cb, void* cb_data);
		};

		// Wrapper stream that splits, encodes and transmits OPC messages.
		class MessageStream
		{
			TransportStream ts;

			// sequential number source
			UInt32 sequence_number;
			UInt32 next_request_id;

			// secure channel id
			UInt32 secure_channel_id;

			static void start_secure_conversation(void* data);
			static void handle_message(const MessageHeader& h, SerializationContext& ctx, void* data);

		public:
			MessageStream(event_base* ev);
			~MessageStream();

			void connect_hostname(const char* hostname, uint16_t port, const char* endpoint, sa_family_t family = AF_UNSPEC);
		};
	};
};

#endif /*TCP_HXX*/
