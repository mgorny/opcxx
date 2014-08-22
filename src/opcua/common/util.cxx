/* OPC UA protocol implementation
 * (c) 2014 Michał Górny
 * Licensed under the terms of the 2-clause BSD license
 */

#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif

#include "util.hxx"

#include <cassert>
#include <stdexcept>

opc_ua::SerializationBuffer::SerializationBuffer()
{
}

opc_ua::SerializationBuffer::SerializationBuffer(evbuffer* new_buf)
	: buf(new_buf)
{
	assert(new_buf);
}

size_t opc_ua::SerializationBuffer::size() const
{
	return evbuffer_get_length(buf);
}

opc_ua::ReadableSerializationBuffer::ReadableSerializationBuffer(evbuffer* new_buf)
	: SerializationBuffer(new_buf)
{
}

opc_ua::ReadableSerializationBuffer::ReadableSerializationBuffer()
{
}

void opc_ua::ReadableSerializationBuffer::read(void* data, size_t length)
{
	ssize_t rd = evbuffer_remove(buf, data, length);

	if (rd < length)
		throw std::runtime_error("Short read when draining the buffer");
}

opc_ua::WritableSerializationBuffer::WritableSerializationBuffer(evbuffer* new_buf)
	: SerializationBuffer(new_buf)
{
}

opc_ua::WritableSerializationBuffer::WritableSerializationBuffer()
{
}

void opc_ua::WritableSerializationBuffer::write(const void* data, size_t length)
{
	if (evbuffer_add(buf, data, length) == -1)
		throw std::runtime_error("Failure appending to buffer");
}

void opc_ua::WritableSerializationBuffer::move(ReadableSerializationBuffer& other)
{
	if (evbuffer_add_buffer(buf, other.buf) == -1)
		throw std::runtime_error("Failure moving buffers");
}

void opc_ua::WritableSerializationBuffer::move(ReadableSerializationBuffer& other, size_t length)
{
	ssize_t rd = evbuffer_remove_buffer(other.buf, buf, length);

	if (rd < length)
		throw std::runtime_error("Short read when moving the buffer");
}

opc_ua::MemorySerializationBuffer::MemorySerializationBuffer()
	: SerializationBuffer(evbuffer_new())
{
}

opc_ua::MemorySerializationBuffer::~MemorySerializationBuffer()
{
	evbuffer_free(buf);
}
