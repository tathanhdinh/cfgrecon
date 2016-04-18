#ifndef INSTRUCTION_H
#define INSTRUCTION_H

//#include "../parsing_helper.h"
#include <pin.H>
extern "C" {
#include "xed-interface.h"
}

#include <cstdint>
#include <string>
#include <memory>
#include <vector>
#include <map>

enum inst_arch_t
{
  IA32_INST_ARCH  = 0,
  IA32E_INST_ARCH = 1
};

class instruction
{
//public:
//  static const xed_machine_mode_enum_t machine_mode = XED_MACHINE_MODE_LEGACY_32;
//  static const xed_address_width_enum_t address_with = XED_ADDRESS_WIDTH_32b;
public:
  static inst_arch_t arch;

 public:
  ADDRINT    address;
  ADDRINT    next_address;
  std::string disassemble;

//  bool has_fall_through;

  bool is_call;
  bool is_branch;
  bool is_syscall;
  bool is_ret;
  bool is_uncond_branch;
//  bool is_special;

  xed_category_enum_t category;
  xed_iclass_enum_t iclass;

//  std::vector<xed_reg_enum_t> src_registers;
//  std::vector<xed_reg_enum_t> dst_registers;
//  std::map<xed_reg_enum_t, uint32_t> read_registers;
//  std::map<xed_reg_enum_t, uint32_t> written_registers;
  std::map<std::string, ADDRINT> read_register;
  std::map<std::string, ADDRINT> written_register;

  std::map<ADDRINT, ADDRINT> load_memory;
  std::map<ADDRINT, ADDRINT> store_memmory;

  ADDRINT load_memory_size;
  ADDRINT store_memory_size;

  std::vector<ADDRINT> static_load_addresses;
  std::vector<ADDRINT> static_store_addresses;

  bool is_memory_read;
  bool is_memory_write;

  bool is_immediate_read;
  ADDRINT immediate_read_value;

 public:
  instruction(ADDRINT ins_addr, const char* opcode_buffer, int opcode_buffer_size);
  instruction(const instruction& other_inst);
};

//typedef std::shared_ptr<instruction> p_instruction_t;
//typedef std::vector<p_instruction_t> p_instructions_t;
//typedef std::map<ADDRINT, p_instruction_t> map_address_instruction_t;
//typedef std::shared_ptr<map_address_instruction_t> p_map_address_instruction_t;
using p_instruction_t             = std::shared_ptr<instruction>;
using p_instructions_t            = std::vector<p_instruction_t>;
using map_address_instruction_t   = std::map<ADDRINT, p_instruction_t>;
using p_map_address_instruction_t = std::shared_ptr<map_address_instruction_t>;

#endif
















