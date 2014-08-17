/* OPC UA protocol implementation
 * (c) 2014 Michał Górny
 * Licensed under the terms of the 2-clause BSD license
 */

#pragma once

#ifndef OPCUA_COMMON_TYPES_HXX
#define OPCUA_COMMON_TYPES_HXX 1

#include <cstdint>
#include <ctime>
#include <string>
#include <vector>

#include <opcua/common/util.hxx>

namespace opc_ua
{
	typedef uint8_t Byte;
	typedef uint16_t UInt16;
	typedef uint32_t UInt32;
	typedef int32_t Int32;
	typedef int64_t Int64;
	typedef double Double;
	// TODO: support NULL value
	typedef std::string String;
	typedef std::string ByteString;

	struct DateTime
	{
		struct timespec ts;

		// non-initializing constructor
		DateTime();
		// construct from struct timespec
		DateTime(struct timespec new_ts);

		// get current time with max available precision
		static DateTime now();
	};

	struct LocalizedText
	{
		String locale;
		String text;
	};

	enum class NodeIdType
	{
		NUMERIC,
	};

	struct NodeId
	{
		NodeIdType type;
		UInt16 ns;
		union {
			UInt32 as_int;
		} id;

		// non-initializing constructor
		NodeId();
		// numeric NodeId
		NodeId(UInt32 node_id, UInt16 node_ns = 0);
	};

	struct Serializer;

	// An abstract structure needing serialization function.
	struct Struct
	{
		virtual void serialize(SerializationContext& ctx, Serializer& s) const = 0;
		virtual void unserialize(SerializationContext& ctx, Serializer& s) = 0;
	};

	// An abstract message.
	struct Message : Struct
	{
		virtual UInt32 node_id() const = 0;
	};

	// Extension object.
	// TODO: currently supports only null contents
	struct ExtensionObject
	{
	};

	template <class T>
	using Array = std::vector<T>;

	class AbstractArraySerialization
	{
	public:
	};

	template <class T>
	class ArraySerialization : public AbstractArraySerialization
	{
		Array<T>& _array;

	public:
		ArraySerialization(Array<T>& array)
			: _array(array)
		{
		}
	};

	// Abstract class defining serializations for known data types.
	struct Serializer
	{
		virtual void serialize(SerializationContext& ctx, Byte i) = 0;
		virtual void serialize(SerializationContext& ctx, UInt16 i) = 0;
		virtual void serialize(SerializationContext& ctx, UInt32 i) = 0;
		virtual void serialize(SerializationContext& ctx, Int32 i) = 0;
		virtual void serialize(SerializationContext& ctx, Int64 i) = 0;
		virtual void serialize(SerializationContext& ctx, Double f) = 0;
		virtual void serialize(SerializationContext& ctx, const String& s) = 0;
		virtual void serialize(SerializationContext& ctx, DateTime t) = 0;
		virtual void serialize(SerializationContext& ctx, const LocalizedText& s) = 0;
		virtual void serialize(SerializationContext& ctx, const NodeId& n) = 0;
		virtual void serialize(SerializationContext& ctx, const Struct& s) = 0;
		virtual void serialize(SerializationContext& ctx, const Array<String>& a) = 0;
		virtual void serialize(SerializationContext& ctx, const ExtensionObject& s) = 0;

		virtual void unserialize(SerializationContext& ctx, Byte& i) = 0;
		virtual void unserialize(SerializationContext& ctx, UInt16& i) = 0;
		virtual void unserialize(SerializationContext& ctx, Int32& i) = 0;
		virtual void unserialize(SerializationContext& ctx, UInt32& i) = 0;
		virtual void unserialize(SerializationContext& ctx, Int64& i) = 0;
		virtual void unserialize(SerializationContext& ctx, Double& f) = 0;
		virtual void unserialize(SerializationContext& ctx, String& s) = 0;
		virtual void unserialize(SerializationContext& ctx, LocalizedText& s) = 0;
		virtual void unserialize(SerializationContext& ctx, DateTime& t) = 0;
		virtual void unserialize(SerializationContext& ctx, NodeId& n) = 0;
		virtual void unserialize(SerializationContext& ctx, Struct& s) = 0;
		virtual void unserialize(SerializationContext& ctx, Array<String>& a) = 0;
		virtual void unserialize(SerializationContext& ctx, ExtensionObject& s) = 0;
	};
};

#endif /*OPCUA_COMMON_TYPES_HXX*/
