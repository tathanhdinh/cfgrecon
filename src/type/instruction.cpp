#include "instruction.h"
#include "../tinyformat.h"

#include <string>
#include <algorithm>
#include <stdexcept>
#include <tuple>

#include <boost/algorithm/string.hpp>

static char disasm_buffer[1000];

static auto parse_disassembled_instruction_from_buffer (const std::string& disasm_buffer) -> std::string
{
  std::vector<std::string> disasm_strs;
  boost::split(disasm_strs, disasm_buffer, boost::is_any_of("\n\r"));
  auto last_str = disasm_strs.back();
  return last_str.substr(6);
}


instruction::instruction(const instruction& other_inst)
{
  this->address = other_inst.address;
  this->next_address = other_inst.next_address;
  this->disassemble = other_inst.disassemble;

  this->is_call = other_inst.is_call;
  this->is_branch = other_inst.is_branch;
  this->is_syscall = other_inst.is_syscall;
  this->is_ret = other_inst.is_ret;
  this->is_uncond_branch = other_inst.is_uncond_branch;

  this->category = other_inst.category;
  this->iclass = other_inst.iclass;

//  this->read_registers = other_inst.read_registers;
//  this->written_registers = other_inst.written_registers;
  this->read_register = other_inst.read_register;
  this->written_register = other_inst.written_register;

//  this->src_mem = other_inst.src_mem;
//  this->dst_mem = other_inst.dst_mem;
  this->load_memory = other_inst.load_memory;
  this->store_memmory = other_inst.store_memmory;

  this->load_memory_size = other_inst.load_memory_size;
  this->store_memory_size = other_inst.store_memory_size;

  this->static_load_addresses = other_inst.static_load_addresses;
  this->static_store_addresses = other_inst.static_store_addresses;

  this->is_memory_read = other_inst.is_memory_read;
  this->is_memory_write = other_inst.is_memory_write;

  this->is_immediate_read = other_inst.is_immediate_read;
  this->immediate_read_value = other_inst.immediate_read_value;
}


#define MEM_LOAD_SIZE          0
#define MEM_STORE_SIZE         1
#define MEM_LOAD_STATIC_ADDRS  2
#define MEM_STORE_STATIC_ADDRS 3
static auto get_memory_access_info (const xed_decoded_inst_t* p_inst) -> std::tuple< ADDRINT, ADDRINT,
                                                                                     std::vector<ADDRINT>, std::vector<ADDRINT> >
{
  auto load_size = ADDRINT{0};
  auto store_size = ADDRINT{0};
  auto static_load_addrs = std::vector<ADDRINT>{};
  auto static_store_addrs = std::vector<ADDRINT>{};

  auto mem_op_num = xed_decoded_inst_number_of_memory_operands(p_inst);

  if (mem_op_num > 0) {

    for (auto op_idx = decltype(mem_op_num){0}; op_idx < mem_op_num; ++op_idx) {

      if (xed_decoded_inst_mem_read(p_inst, op_idx)) {
        auto mem_dsplc = xed_decoded_inst_get_memory_displacement(p_inst, op_idx);

        auto base_reg = xed_decoded_inst_get_base_reg(p_inst, op_idx);
        auto index_reg = xed_decoded_inst_get_index_reg(p_inst, op_idx);

        load_size = xed_decoded_inst_get_memory_operand_length(p_inst, op_idx);

        if (base_reg == XED_REG_INVALID && index_reg == XED_REG_INVALID) {          
          for (auto idx = uint32_t{0}; idx < load_size; ++idx) {
            static_load_addrs.push_back(mem_dsplc + idx);
          }
        }
      }

      if (xed_decoded_inst_mem_written(p_inst, op_idx)) {
        auto mem_dsplc = xed_decoded_inst_get_memory_displacement(p_inst, op_idx);

        auto base_reg = xed_decoded_inst_get_base_reg(p_inst, op_idx);
        auto index_reg = xed_decoded_inst_get_index_reg(p_inst, op_idx);

        store_size = xed_decoded_inst_get_memory_operand_length(p_inst, op_idx);

        if (base_reg == XED_REG_INVALID && index_reg == XED_REG_INVALID) {
          for (auto idx = decltype(store_size){0}; idx < store_size; ++idx) {
            static_store_addrs.push_back(mem_dsplc + idx);
          }
        }
      }
    }
  }

  return std::make_tuple(load_size, store_size, static_load_addrs, static_store_addrs);
}

instruction::instruction(ADDRINT ins_addr, const char* opcode_buffer, int opcode_buffer_size)
{
//  tfm::printfln("0x%x %d", ins_addr, opcode_buffer_size);
  this->address = ins_addr;

  auto xed_inst = xed_decoded_inst_t{};
  if (this->arch == IA32_INST_ARCH) {
//    tfm::printfln("set 32 bit decoding mode");
    xed_decoded_inst_set_mode(&xed_inst, XED_MACHINE_MODE_LEGACY_32, XED_ADDRESS_WIDTH_32b);
  }
  else {
//    tfm::printfln("set 64 bit decoding mode");
    xed_decoded_inst_set_mode(&xed_inst, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);
  }

//  tfm::printfln("opcode buffer size: %d", opcode_buffer_size);
  auto decode_err = xed_decode(&xed_inst, XED_STATIC_CAST(const xed_uint8_t*, opcode_buffer), opcode_buffer_size);
  if (decode_err != XED_ERROR_NONE) {
    tfm::printfln("0x%x: ", ins_addr);
    auto tmp_buff = reinterpret_cast<const uint8_t*>(opcode_buffer);
    for (int i = 0; i < opcode_buffer_size; ++i) {
      tfm::printf("%x ",tmp_buff[i]);
    }
    tfm::printfln("instruction decoding error");
    //throw std::logic_error("instruction decoding error");
  }
  else {
    std::fill_n(disasm_buffer, 1000, 0);
    xed_decoded_inst_dump_xed_format(&xed_inst, disasm_buffer, 128, ins_addr);
    auto disasm_err = xed_format_context(XED_SYNTAX_INTEL, &xed_inst, disasm_buffer, 128, ins_addr, nullptr, nullptr);
    if (disasm_err == 0) throw std::logic_error("instruction disassembling error");

    this->disassemble = std::string(disasm_buffer);

  //  xed_decoded_inst_dump(&xed_inst, disasm_buffer, 1000);
  //  this->disassemble = parse_disassembled_instruction_from_buffer(disasm_buffer);

    this->category = xed_decoded_inst_get_category(&xed_inst);
    this->is_call = (this->category == XED_CATEGORY_CALL);
    this->is_branch = (this->category == XED_CATEGORY_COND_BR);
    this->is_ret = (this->category == XED_CATEGORY_RET);
    this->is_uncond_branch = (this->category == XED_CATEGORY_UNCOND_BR);

    this->iclass = xed_decoded_inst_get_iclass(&xed_inst);

  //  auto xi = xed_decoded_inst_inst(&xed_inst);
  //  auto ins_operand_num = xed_inst_noperands(xi);
  //  auto ins_operand_num = xed_decoded_inst_noperands(&xed_inst);

  //  for (auto idx = decltype(ins_operand_num){0}; idx < ins_operand_num; ++idx) {
  //    auto ins_operand = xed_inst_operand(xi, idx);
  //    auto operand_name = xed_operand_name(ins_operand);

  //    if (xed_operand_is_register(operand_name)) {
  //      if (xed_operand_read(ins_operand)) {
  //        auto xed_read_reg = xed_decoded_inst_get_reg(&xed_inst, operand_name);
  ////        this->src_registers.push_back(xed_read_reg);
  //        this->read_registers[xed_read_reg] = 0x0;
  //      }

  //      if (xed_operand_written(ins_operand)) {
  //        auto xed_written_reg = xed_decoded_inst_get_reg(&xed_inst, operand_name);
  ////        this->dst_registers.push_back(xed_written_reg);
  ////        INS_XedExactMapToPinReg(xed_written_reg);
  //        this->written_registers[xed_written_reg] = 0x0;
  //      }
  //    }
  //  }

  //  tfm::printfln("%s src: %d dst: %d", this->disassemble, this->read_registers.size(), this->written_registers.size());

    this->is_memory_read = false; this->is_memory_write = false;
    auto ins_mem_noperands = xed_decoded_inst_number_of_memory_operands(&xed_inst);
    for (decltype(ins_mem_noperands) mem_idx = 0; mem_idx < ins_mem_noperands; ++mem_idx) {
      if (xed_decoded_inst_mem_read(&xed_inst, mem_idx)) this->is_memory_read = true;
      if (xed_decoded_inst_mem_written(&xed_inst, mem_idx)) this->is_memory_write = true;
    }

  //  tfm::printfln("%s", this->disassemble);
    auto mem_access_info = get_memory_access_info(&xed_inst);

    this->load_memory_size = std::get<MEM_LOAD_SIZE>(mem_access_info);
    this->store_memory_size = std::get<MEM_STORE_SIZE>(mem_access_info);

    this->static_load_addresses = std::get<MEM_LOAD_STATIC_ADDRS>(mem_access_info);
    this->static_store_addresses = std::get<MEM_STORE_STATIC_ADDRS>(mem_access_info);

    auto ins_operand_num = xed_decoded_inst_noperands(&xed_inst);
    auto inst = xed_decoded_inst_inst(&xed_inst);
    for (auto i = decltype(ins_operand_num){0}; i < ins_operand_num; ++i) {
      auto operand = xed_inst_operand(inst, i);
      auto operand_name = xed_operand_name(operand);

      if (operand_name == XED_OPERAND_IMM0) {
        this->is_immediate_read = true;
        this->immediate_read_value = xed_decoded_inst_get_unsigned_immediate(&xed_inst);
        break;
      }
    }
  }

//  tfm::printfln("haha\n");
}
