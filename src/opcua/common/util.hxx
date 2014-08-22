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

	// A base class for buffers used for serialization.
	class SerializationBuffer
	{
	protected:
		evbuffer* buf;

		SerializationBuffer(evbuffer* new_buf);

	public:
		// get length of data stored in the buffer
		size_t size() const;
	};

	// Serialization buffer that is associated with a readable stream.
	class ReadableSerializationBuffer : public virtual SerializationBuffer
	{
		friend class WritableSerializationBuffer;

	public:
		ReadableSerializationBuffer(evbuffer* new_buf);

		// read data from the buffer
		void read(void* data, size_t length);
	};

	// Serialization buffer that is associated with a writable stream.
	class WritableSerializationBuffer : public virtual SerializationBuffer
	{
	public:
		WritableSerializationBuffer(evbuffer* new_buf);

		// append new block of data to the buffer
		void write(const void* data, size_t length);

		// move data from another buffer into this one
		void move(ReadableSerializationBuffer& other);
		// move part of data from another buffer into this one
		void move(ReadableSerializationBuffer& other, size_t length);
	};

	// Serializes buffer that uses private memory storage for underlying
	// data. This works as a FIFO loopback -- writes append to the end
	// of the buffer, reads remove data from the beginning.
	class MemorySerializationBuffer : public ReadableSerializationBuffer,
			public WritableSerializationBuffer
	{
	public:
		MemorySerializationBuffer();
		~MemorySerializationBuffer();
	};
};

#endif /*OPCUA_COMMON_UTIL_HXX*/
