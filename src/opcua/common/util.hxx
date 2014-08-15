/* OPC UA protocol implementation
 * (c) 2014 Michał Górny
 * Licensed under the terms of the 2-clause BSD license
 */

#pragma once

#ifndef OPCUA_COMMON_UTIL_HXX
#define OPCUA_COMMON_UTIL_HXX 1

#include <event2/buffer.h>

namespace opc_ua
{
	// for use in assertions
	constexpr bool not_reached = false;

	// Context to use for serialization functions. Mostly serves
	// as an abstract wrapper for stream-associated buffer.
	class SerializationContext
	{
	protected:
		evbuffer* _buf;

	public:
		SerializationContext(evbuffer* buf);

		// get length of data stored in the buffer
		size_t size();
		// read data from the buffer
		void read(void* data, size_t size);
		// append new block of data to the buffer
		void write(const void* data, size_t size);
		// copy contents of a buffer associated with another
		// SerializationContext to the buffer
		void write(const SerializationContext& ctx);

		// move contents of a buffer associated with another
		// SerializationContext
		void move(SerializationContext& orig, size_t length);
	};

	// Context used to store part of serialized data. Allocates
	// a local buffer for the data.
	class TemporarySerializationContext : public SerializationContext
	{
	public:
		TemporarySerializationContext();
		~TemporarySerializationContext();

		void clear();
	};
};

#endif /*OPCUA_COMMON_UTIL_HXX*/
