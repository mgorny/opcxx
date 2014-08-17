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
	static_assert(sizeof(double) == 8, "only IEEE754 64-bit double supported ATM");

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
		GUID,
		BYTE_STRING,
	};

	struct GUID
	{
		// the specifications suggests splitting it into 4 fields...
		// but let's keep it simple
		Byte guid[16];
	};

	struct NodeId
	{
		NodeIdType type;
		UInt16 ns;
		union {
			UInt32 as_int;
			GUID as_guid;
		};
		ByteString as_bytestring;

		// non-initializing constructor
		NodeId();
		// numeric NodeId
		NodeId(UInt32 node_id, UInt16 node_ns = 0);
		// GUID NodeId
		NodeId(const GUID& node_id, UInt16 node_ns);
		// ByteString NodeId
		NodeId(const ByteString& node_id, UInt16 node_ns);
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
		virtual size_t size() const = 0;
		virtual void serialize_all(SerializationContext& ctx, Serializer& s) const = 0;
	};

	template <class T>
	class ArraySerialization : public AbstractArraySerialization
	{
		const Array<T>& _array;

	public:
		ArraySerialization(const Array<T>& array);
		virtual size_t size() const;
		virtual void serialize_all(SerializationContext& ctx, Serializer& s) const;
	};

	class AbstractArrayUnserialization
	{
	public:
		virtual void clear() const = 0;
		virtual void unserialize_n(SerializationContext& ctx, Serializer& s, size_t count) const = 0;
	};

	template <class T>
	class ArrayUnserialization : public AbstractArrayUnserialization
	{
		Array<T>& _array;

	public:
		ArrayUnserialization(Array<T>& array);
		virtual void clear() const;
		virtual void unserialize_n(SerializationContext& ctx, Serializer& s, size_t count) const;
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
		virtual void serialize(SerializationContext& ctx, const GUID& g) = 0;
		virtual void serialize(SerializationContext& ctx, const NodeId& n) = 0;
		virtual void serialize(SerializationContext& ctx, const Struct& s) = 0;
		virtual void serialize(SerializationContext& ctx, const ExtensionObject& s) = 0;
		virtual void serialize(SerializationContext& ctx, const AbstractArraySerialization& a) = 0;

		virtual void unserialize(SerializationContext& ctx, Byte& i) = 0;
		virtual void unserialize(SerializationContext& ctx, UInt16& i) = 0;
		virtual void unserialize(SerializationContext& ctx, Int32& i) = 0;
		virtual void unserialize(SerializationContext& ctx, UInt32& i) = 0;
		virtual void unserialize(SerializationContext& ctx, Int64& i) = 0;
		virtual void unserialize(SerializationContext& ctx, Double& f) = 0;
		virtual void unserialize(SerializationContext& ctx, String& s) = 0;
		virtual void unserialize(SerializationContext& ctx, LocalizedText& s) = 0;
		virtual void unserialize(SerializationContext& ctx, DateTime& t) = 0;
		virtual void unserialize(SerializationContext& ctx, GUID& g) = 0;
		virtual void unserialize(SerializationContext& ctx, NodeId& n) = 0;
		virtual void unserialize(SerializationContext& ctx, Struct& s) = 0;
		virtual void unserialize(SerializationContext& ctx, ExtensionObject& s) = 0;
		virtual void unserialize(SerializationContext& ctx, const AbstractArrayUnserialization& a) = 0;
	};

	// serializer implementation
	template <class T>
	ArraySerialization<T>::ArraySerialization(const Array<T>& array)
		: _array(array)
	{
	}

	template <class T>
	size_t ArraySerialization<T>::size() const
	{
		return _array.size();
	}

	template <class T>
	void ArraySerialization<T>::serialize_all(SerializationContext& ctx, Serializer& s) const
	{
		for (const T& i : _array)
			s.serialize(ctx, i);
	}

	// unserializer implementation
	template <class T>
	ArrayUnserialization<T>::ArrayUnserialization(Array<T>& array)
		: _array(array)
	{
	}

	template <class T>
	void ArrayUnserialization<T>::clear() const
	{
		_array.clear();
	}

	template <class T>
	void ArrayUnserialization<T>::unserialize_n(SerializationContext& ctx, Serializer& s, size_t count) const
	{
		_array.resize(count);

		for (T& i : _array)
			s.unserialize(ctx, i);
	}
};

#endif /*OPCUA_COMMON_TYPES_HXX*/
