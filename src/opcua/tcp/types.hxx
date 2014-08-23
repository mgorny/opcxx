/* OPC UA protocol implementation
 * (c) 2014 Michał Górny
 * Licensed under the terms of the 2-clause BSD license
 */

#pragma once

#ifndef OPCUA_TCP_TYPES_HXX
#define OPCUA_TCP_TYPES_HXX 1

#include <opcua/common/struct.hxx>
#include <opcua/common/types.hxx>
#include <opcua/common/util.hxx>

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

		struct ProtocolInfo
		{
			UInt32 protocol_version;
			UInt32 receive_buffer_size;
			UInt32 send_buffer_size;
			UInt32 max_message_size;
			UInt32 max_chunk_count;
		};

		extern const ProtocolInfo libevent_protocol_info;

		struct HelloMessage
		{
			ProtocolInfo protocol_info;
			String endpoint_url;
		};

		struct AcknowledgeMessage
		{
			ProtocolInfo protocol_info;
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
			virtual void serialize(WritableSerializationBuffer& ctx, Boolean b);
			virtual void serialize(WritableSerializationBuffer& ctx, Byte i);
			virtual void serialize(WritableSerializationBuffer& ctx, UInt16 i);
			virtual void serialize(WritableSerializationBuffer& ctx, UInt32 i);
			virtual void serialize(WritableSerializationBuffer& ctx, Int32 i);
			virtual void serialize(WritableSerializationBuffer& ctx, Int64 i);
			virtual void serialize(WritableSerializationBuffer& ctx, Double f);
			virtual void serialize(WritableSerializationBuffer& ctx, const String& s);
			virtual void serialize(WritableSerializationBuffer& ctx, DateTime t);
			virtual void serialize(WritableSerializationBuffer& ctx, const LocalizedText& s);
			virtual void serialize(WritableSerializationBuffer& ctx, const GUID& g);
			virtual void serialize(WritableSerializationBuffer& ctx, const NodeId& n);
			virtual void serialize(WritableSerializationBuffer& ctx, const Struct& s);
			virtual void serialize(WritableSerializationBuffer& ctx, const ExtensionObject& s);
			virtual void serialize(WritableSerializationBuffer& ctx, const Variant& v);
			virtual void serialize(WritableSerializationBuffer& ctx, const AbstractArraySerialization& a);

			virtual void unserialize(ReadableSerializationBuffer& ctx, Boolean& b);
			virtual void unserialize(ReadableSerializationBuffer& ctx, Byte& i);
			virtual void unserialize(ReadableSerializationBuffer& ctx, UInt16& i);
			virtual void unserialize(ReadableSerializationBuffer& ctx, Int32& i);
			virtual void unserialize(ReadableSerializationBuffer& ctx, UInt32& i);
			virtual void unserialize(ReadableSerializationBuffer& ctx, Int64& i);
			virtual void unserialize(ReadableSerializationBuffer& ctx, Double& f);
			virtual void unserialize(ReadableSerializationBuffer& ctx, String& s);
			virtual void unserialize(ReadableSerializationBuffer& ctx, DateTime& t);
			virtual void unserialize(ReadableSerializationBuffer& ctx, LocalizedText& s);
			virtual void unserialize(ReadableSerializationBuffer& ctx, GUID& g);
			virtual void unserialize(ReadableSerializationBuffer& ctx, NodeId& n);
			virtual void unserialize(ReadableSerializationBuffer& ctx, Struct& s);
			virtual void unserialize(ReadableSerializationBuffer& ctx, ExtensionObject& s);
			virtual void unserialize(ReadableSerializationBuffer& ctx, Variant& v);
			virtual void unserialize(ReadableSerializationBuffer& ctx, const AbstractArrayUnserialization& a);

			// UA TCP specific types
			void serialize(WritableSerializationBuffer& ctx, MessageIsFinal b);
			void serialize(WritableSerializationBuffer& ctx, MessageType t);
			void serialize(WritableSerializationBuffer& ctx, const MessageHeader& h);
			void serialize(WritableSerializationBuffer& ctx, const SecureConversationMessageHeader& h);
			void serialize(WritableSerializationBuffer& ctx, const ProtocolInfo& proto);
			void serialize(WritableSerializationBuffer& ctx, const HelloMessage& msg);
			void serialize(WritableSerializationBuffer& ctx, const AcknowledgeMessage& msg);
			void serialize(WritableSerializationBuffer& ctx, const ErrorMessage& msg);
			void serialize(WritableSerializationBuffer& ctx, const AsymmetricAlgorithmSecurityHeader& h);
			void serialize(WritableSerializationBuffer& ctx, const SymmetricAlgorithmSecurityHeader& h);
			void serialize(WritableSerializationBuffer& ctx, const SequenceHeader& h);

			void unserialize(ReadableSerializationBuffer& ctx, MessageIsFinal& b);
			void unserialize(ReadableSerializationBuffer& ctx, MessageType& t);
			void unserialize(ReadableSerializationBuffer& ctx, MessageHeader& h);
			void unserialize(ReadableSerializationBuffer& ctx, ProtocolInfo& proto);
			void unserialize(ReadableSerializationBuffer& ctx, HelloMessage& msg);
			void unserialize(ReadableSerializationBuffer& ctx, AcknowledgeMessage& msg);
			void unserialize(ReadableSerializationBuffer& ctx, ErrorMessage& msg);
			void unserialize(ReadableSerializationBuffer& ctx, AsymmetricAlgorithmSecurityHeader& h);
			void unserialize(ReadableSerializationBuffer& ctx, SymmetricAlgorithmSecurityHeader& h);
			void unserialize(ReadableSerializationBuffer& ctx, SequenceHeader& h);
		};
	};
};

#endif /*OPCUA_TCP_TYPES_HXX*/
