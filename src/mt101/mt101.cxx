
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif

#include "mt101.hxx"

#include <cassert>
#include <cerrno>
#include <stdexcept>
#include <vector>

mt101::ModbusError::ModbusError(const char* op, int error)
{
	// XXX
}

mt101::MT101::MT101()
	: _rtu(0)
{
}

mt101::MT101::~MT101()
{
	if (_rtu)
		disconnect();
}

void mt101::MT101::connect()
{
	if (_rtu)
		throw std::logic_error("MT101 already connected (when connect() called)!");

	_rtu = modbus_new_rtu("/dev/ttyS0", 9600, 'N', 8, 1);
	if (!_rtu)
		throw ModbusError("modbus_new_rtu", errno);

	// (temporary)
	modbus_set_debug(_rtu, 1);

	if (modbus_set_slave(_rtu, 1))
		throw ModbusError("modbus_set_slave(1)", errno);
	if (modbus_connect(_rtu))
		throw ModbusError("modbus_connect()", errno);
}

void mt101::MT101::disconnect()
{
	if (!_rtu)
		throw std::logic_error("MT101 not connected (when disconnect() called)!");

	modbus_close(_rtu);
	modbus_free(_rtu);

	// prevent post-free access
	_rtu = 0;
}

#include <iostream>

void mt101::MT101::fetch()
{
	if (modbus_read_input_bits(_rtu, 0, consts::binary_inputs_length,
			_binary_inputs.data()) != consts::binary_inputs_length)
		throw ModbusError("modbus_read_input_bits()", errno);

	if (modbus_read_bits(_rtu, 0, consts::binary_outputs_length,
			_binary_outputs.data()) != consts::binary_outputs_length)
		throw ModbusError("modbus_read_bits()", errno);

	if (modbus_read_input_registers(_rtu, 0, consts::binary_inputs_length,
				_analog_inputs.data()) != consts::binary_inputs_length)
		throw ModbusError("modbus_read_input_registers()", errno);

	if (modbus_read_registers(_rtu, 0, consts::internal_registers_length,
				_internal_registers.data()) != consts::internal_registers_length)
		throw ModbusError("modbus_read_registers()", errno);

	// convert binary data to bitset
}

bool mt101::MT101::get_binary_input_state(size_t addr)
{
	assert(_rtu);
	assert(addr <= consts::binary_inputs_length);

	return _binary_inputs[addr];
}

bool mt101::MT101::get_binary_output_state(size_t addr)
{
	assert(_rtu);
	assert(addr <= consts::binary_outputs_length);

	return _binary_outputs[addr];
}

uint16_t mt101::MT101::get_analog_input_value(size_t addr)
{
	assert(_rtu);
	assert(addr <= consts::analog_inputs_length);

	return _analog_inputs[addr];
}

uint16_t mt101::MT101::get_internal_register_value(size_t addr)
{
	assert(_rtu);
	assert(addr <= consts::internal_registers_length);

	return _internal_registers[addr];
}

uint32_t mt101::MT101::get_internal_register_long(size_t addr)
{
	assert(_rtu);
	assert(addr+1 <= consts::internal_registers_length);

	return _internal_registers[addr] << 16 | _internal_registers[addr+1];
}

void mt101::MT101::set_binary_output_state(size_t addr, bool new_state)
{
	assert(_rtu);
	assert(addr <= consts::binary_outputs_length);

	write_queue[addr] = new_state;
}

void mt101::MT101::flush()
{
	size_t first_addr = 0, last_addr = 0;
	std::vector<uint8_t> write_data;

	// write_queue is sorted, so merge consecutive writes into one
	for (auto& kv : write_queue)
	{
		size_t addr = kv.first;
		bool value = kv.second;

		if (addr - 1 != last_addr)
		{
			if (!write_data.empty())
			{
				// perform the write
				modbus_write_bits(_rtu, first_addr, write_data.size(), write_data.data());
				write_data.clear();
			}

			first_addr = addr;
		}
		last_addr = addr;
		write_data.push_back(value);
	}

	if (!write_data.empty())
	{
		// perform the write
		modbus_write_bits(_rtu, first_addr, write_data.size(), write_data.data());
		write_data.clear();
	}

	write_queue.clear();
}
