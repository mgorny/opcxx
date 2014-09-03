
#pragma once

#ifndef MT101_HXX
#define MT101_HXX 1

#include <cstdint>
#include <array>
#include <exception>

#include <modbus.h>

namespace mt101
{
	struct consts
	{
		// lengths of basic memory regions
		// used to construct internal buffers
		static const size_t binary_inputs_length = 0x60; // 0x03c0;
		static const size_t binary_outputs_length = 0x50; //0x0100;
		static const size_t analog_inputs_length = 0x60; //0x0540;
		static const size_t internal_registers_length = 0x60; // 0x0300;

		// memory map
		// binary inputs
		static const size_t IQ1 = 0x0000;
		static const size_t IQ2 = 0x0001;
		static const size_t IQ3 = 0x0002;
		static const size_t IQ4 = 0x0003;
		static const size_t IQ5 = 0x0004;
		static const size_t IQ6 = 0x0005;
		static const size_t IQ7 = 0x0006;
		static const size_t IQ8 = 0x0007;
		static const size_t I1 = 0x0008;
		static const size_t I2 = 0x0009;
		static const size_t I3 = 0x000a;
		static const size_t I4 = 0x000b;
		static const size_t I5 = 0x000c;
		static const size_t I6 = 0x000d;
		static const size_t I7 = 0x000e;
		static const size_t I8 = 0x000f;

		// binary outputs
		static const size_t Q1 = 0x0000;
		static const size_t Q2 = 0x0001;
		static const size_t Q3 = 0x0002;
		static const size_t Q4 = 0x0003;
		static const size_t Q5 = 0x0004;
		static const size_t Q6 = 0x0005;
		static const size_t Q7 = 0x0006;
		static const size_t Q8 = 0x0007;

		// analog inputs
		static const size_t AN1 = 0x0004;
		static const size_t AN2 = 0x0005;
		static const size_t RTC_Sec = 0x0006;
		static const size_t RTC_Min = 0x0007;
		static const size_t RTC_Hour = 0x0008;
		static const size_t RTC_DofW = 0x0009;
		static const size_t RTC_Day = 0x000a;
		static const size_t RTC_Mon = 0x000b;
		static const size_t RTC_Year = 0x000c;
		static const size_t AQ1 = 0x0021;
		static const size_t AQ2 = 0x0022;
		static const size_t AQ3 = 0x0023;
		static const size_t AQ4 = 0x0024;
		static const size_t AQ5 = 0x0025;
		static const size_t AQ6 = 0x0026;
		static const size_t AQ7 = 0x0027;
		static const size_t AQ8 = 0x0028;
		static const size_t AI1 = 0x0029;
		static const size_t AI2 = 0x002a;
		static const size_t AI3 = 0x002b;
		static const size_t AI4 = 0x002c;
		static const size_t AI5 = 0x002d;
		static const size_t AI6 = 0x002e;
		static const size_t AI7 = 0x002f;
		static const size_t AI8 = 0x0030;

		// internal registers
		static const size_t CNT_Q1 = 0x0000;
		static const size_t CNT_Q2 = 0x0002;
		static const size_t CNT_Q3 = 0x0004;
		static const size_t CNT_Q4 = 0x0006;
		static const size_t CNT_Q5 = 0x0008;
		static const size_t CNT_Q6 = 0x000a;
		static const size_t CNT_Q7 = 0x000c;
		static const size_t CNT_Q8 = 0x000e;
		static const size_t CNT_I1 = 0x0010;
		static const size_t CNT_I2 = 0x0012;
		static const size_t CNT_I3 = 0x0014;
		static const size_t CNT_I4 = 0x0016;
		static const size_t CNT_I5 = 0x0018;
		static const size_t CNT_I6 = 0x001a;
		static const size_t CNT_I7 = 0x001c;
		static const size_t CNT_I8 = 0x001e;
	};

	class ModbusError : public std::exception
	{
	public:
		ModbusError(const char* op, int error);
	};

	class MT101
	{
		modbus_t* _rtu;

		std::array<uint8_t, consts::binary_inputs_length> _binary_inputs;
		std::array<uint8_t, consts::binary_outputs_length> _binary_outputs;
		std::array<uint16_t, consts::analog_inputs_length> _analog_inputs;
		std::array<uint16_t, consts::internal_registers_length> _internal_registers;

	public:
		MT101();
		~MT101();

		// Establish connection to MT101.
		void connect();
		// Close connection to MT101.
		void disconnect();

		// Fetch MT101 registers into internal buffers.
		void fetch();

		// Read data from internal buffers.
		bool get_binary_input_state(size_t addr);
		bool get_binary_output_state(size_t addr);
		uint16_t get_analog_input_value(size_t addr);
		uint16_t get_internal_register_value(size_t addr);
		uint32_t get_internal_register_long(size_t addr);
	};
};

#endif /*MT101_HXX*/
