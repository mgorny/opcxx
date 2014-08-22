/* OPC UA protocol implementation
 * (c) 2014 Michał Górny
 * Licensed under the terms of the 2-clause BSD license
 */

#pragma once

#ifndef OPCUA_COMMON_TYPES_HXX
#define OPCUA_COMMON_TYPES_HXX 1

#include <array>
#include <cstdint>
#include <ctime>
#include <memory>
#include <string>
#include <vector>

#include <opcua/common/util.hxx>

namespace opc_ua
{
	static_assert(sizeof(double) == 8, "only IEEE754 64-bit double supported ATM");

	typedef bool Boolean;
	typedef uint8_t Byte;
	typedef uint16_t UInt16;
	typedef uint32_t UInt32;
	typedef int32_t Int32;
	typedef int64_t Int64;
	typedef double Double;
	// TODO: support NULL value
	typedef std::string String;
	typedef std::string ByteString;
	typedef std::string CharArray;

	struct DateTime
	{
		struct timespec ts;

		DateTime();
		DateTime(struct timespec new_ts);

		// get current time with max available precision
		static DateTime now();
	};

	struct LocalizedText
	{
		CharArray locale;
		CharArray text;
	};

	enum class NodeIdType
	{
		NUMERIC,
		GUID,
		STRING,
		BYTE_STRING,
	};

	struct GUID
	{
		// the specifications suggests splitting it into 4 fields...
		// but let's keep it simple
		std::array<Byte, 16> guid;

		bool operator==(const GUID& other) const;
		bool operator!=(const GUID& other) const;
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
		CharArray as_chararray;

		// Numeric NodeId
		NodeId(UInt32 node_id = 0, UInt16 node_ns = 0);
		// GUID NodeId
		NodeId(const GUID& node_id, UInt16 node_ns);
		// String NodeId
		NodeId(const CharArray& node_id, UInt16 node_ns);
		// ByteString NodeId
		NodeId(const ByteString& node_id, UInt16 node_ns, int unused);

		bool operator==(const NodeId& other) const;
		bool operator!=(const NodeId& other) const;
	};

	struct Serializer;

	// An abstract structure needing serialization function.
	struct Struct
	{
		virtual void serialize(WritableSerializationBuffer& ctx, Serializer& s) const = 0;
		virtual void unserialize(ReadableSerializationBuffer& ctx, Serializer& s) = 0;
		virtual UInt32 get_node_id() const = 0;
	};

	// An abstract message.
	struct Message : Struct
	{
	};

	// Extension object.
	// TODO: decoding
	struct ExtensionObject
	{
		std::unique_ptr<Struct> inner_object;

		ExtensionObject(std::unique_ptr<Struct> obj = nullptr);
	};

	template <class T>
	using Array = std::vector<T>;

	enum class VariantType
	{
		NONE = 0,
		BOOLEAN = 1,
		BYTE = 3,
		UINT16 = 5,
		INT32 = 6,
		UINT32 = 7,
		INT64 = 8,
		DOUBLE = 11,
		STRING = 12,
		DATETIME = 13,
		GUID = 14,
		BYTESTRING = 15,
	};

	struct Variant
	{
		VariantType variant_type;

		union
		{
			Boolean as_boolean;
			Byte as_byte;
			UInt16 as_uint16;
			Int32 as_int32;
			UInt32 as_uint32;
			Int64 as_int64;
			Double as_double;
			DateTime as_datetime;
			GUID as_guid;
		};

		String as_string;
		ByteString as_bytestring;

		Variant();
		Variant(Boolean b);
		Variant(Byte b);
		Variant(UInt16 i);
		Variant(Int32 i);
		Variant(UInt32 i);
		Variant(Int64 i);
		Variant(Double f);
		Variant(const String& s);
		Variant(DateTime dt);
		Variant(const GUID& g);
		Variant(const ByteString& s, int unused);
	};

	class AbstractArraySerialization
	{
	public:
		virtual size_t size() const = 0;
		virtual void serialize_all(WritableSerializationBuffer& ctx, Serializer& s) const = 0;
	};

	template <class T>
	class ArraySerialization : public AbstractArraySerialization
	{
		const Array<T>& _array;

	public:
		ArraySerialization(const Array<T>& array);
		virtual size_t size() const;
		virtual void serialize_all(WritableSerializationBuffer& ctx, Serializer& s) const;
	};

	class AbstractArrayUnserialization
	{
	public:
		virtual void clear() const = 0;
		virtual void unserialize_n(ReadableSerializationBuffer& ctx, Serializer& s, size_t count) const = 0;
	};

	template <class T>
	class ArrayUnserialization : public AbstractArrayUnserialization
	{
		Array<T>& _array;

	public:
		ArrayUnserialization(Array<T>& array);
		virtual void clear() const;
		virtual void unserialize_n(ReadableSerializationBuffer& ctx, Serializer& s, size_t count) const;
	};

	// Abstract class defining serializations for known data types.
	struct Serializer
	{
		virtual void serialize(WritableSerializationBuffer& ctx, Boolean b) = 0;
		virtual void serialize(WritableSerializationBuffer& ctx, Byte i) = 0;
		virtual void serialize(WritableSerializationBuffer& ctx, UInt16 i) = 0;
		virtual void serialize(WritableSerializationBuffer& ctx, UInt32 i) = 0;
		virtual void serialize(WritableSerializationBuffer& ctx, Int32 i) = 0;
		virtual void serialize(WritableSerializationBuffer& ctx, Int64 i) = 0;
		virtual void serialize(WritableSerializationBuffer& ctx, Double f) = 0;
		virtual void serialize(WritableSerializationBuffer& ctx, const String& s) = 0;
		virtual void serialize(WritableSerializationBuffer& ctx, DateTime t) = 0;
		virtual void serialize(WritableSerializationBuffer& ctx, const LocalizedText& s) = 0;
		virtual void serialize(WritableSerializationBuffer& ctx, const GUID& g) = 0;
		virtual void serialize(WritableSerializationBuffer& ctx, const NodeId& n) = 0;
		virtual void serialize(WritableSerializationBuffer& ctx, const Struct& s) = 0;
		virtual void serialize(WritableSerializationBuffer& ctx, const ExtensionObject& s) = 0;
		virtual void serialize(WritableSerializationBuffer& ctx, const Variant& v) = 0;
		virtual void serialize(WritableSerializationBuffer& ctx, const AbstractArraySerialization& a) = 0;

		virtual void unserialize(ReadableSerializationBuffer& ctx, Boolean& b) = 0;
		virtual void unserialize(ReadableSerializationBuffer& ctx, Byte& i) = 0;
		virtual void unserialize(ReadableSerializationBuffer& ctx, UInt16& i) = 0;
		virtual void unserialize(ReadableSerializationBuffer& ctx, Int32& i) = 0;
		virtual void unserialize(ReadableSerializationBuffer& ctx, UInt32& i) = 0;
		virtual void unserialize(ReadableSerializationBuffer& ctx, Int64& i) = 0;
		virtual void unserialize(ReadableSerializationBuffer& ctx, Double& f) = 0;
		virtual void unserialize(ReadableSerializationBuffer& ctx, String& s) = 0;
		virtual void unserialize(ReadableSerializationBuffer& ctx, LocalizedText& s) = 0;
		virtual void unserialize(ReadableSerializationBuffer& ctx, DateTime& t) = 0;
		virtual void unserialize(ReadableSerializationBuffer& ctx, GUID& g) = 0;
		virtual void unserialize(ReadableSerializationBuffer& ctx, NodeId& n) = 0;
		virtual void unserialize(ReadableSerializationBuffer& ctx, Struct& s) = 0;
		virtual void unserialize(ReadableSerializationBuffer& ctx, ExtensionObject& s) = 0;
		virtual void unserialize(ReadableSerializationBuffer& ctx, Variant& v) = 0;
		virtual void unserialize(ReadableSerializationBuffer& ctx, const AbstractArrayUnserialization& a) = 0;
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
	void ArraySerialization<T>::serialize_all(WritableSerializationBuffer& ctx, Serializer& s) const
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
	void ArrayUnserialization<T>::unserialize_n(ReadableSerializationBuffer& ctx, Serializer& s, size_t count) const
	{
		_array.resize(count);

		for (T& i : _array)
			s.unserialize(ctx, i);
	}

	// utility functions
	ByteString random_nonce();
};

#endif /*OPCUA_COMMON_TYPES_HXX*/
