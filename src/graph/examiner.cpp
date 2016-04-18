#include "../type/instruction.h"
#include "../tinyformat.h"

#include <fstream>
#include <set>

extern p_instructions_t trace;

using chunk_mem_access_t = std::pair< std::vector<ADDRINT>, std::vector<ADDRINT> >;

using p_chunk_mem_access_t = std::shared_ptr<const chunk_mem_access_t>;
using chunk_index_pair_t = std::pair<p_chunk_mem_access_t, uint32_t>;
using chunk_index_pairs_t = std::vector<chunk_index_pair_t>;

bool is_equal(const p_chunk_mem_access_t chunk_a, p_chunk_mem_access_t chunk_b)
{
  return (/*std::get<0>(*chunk_a) == std::get<0>(*chunk_b) &&*/
          std::get<1>(*chunk_a) == std::get<1>(*chunk_b));
}

#define MEM_LOAD true
#define MEM_STORE false
template<bool load_or_store>
static auto get_memory_access_addresses (p_instructions_t trace) -> std::vector<ADDRINT>
{
  auto access_mem_addrs = std::vector<ADDRINT>{};

  for (const auto& ins : trace) {
    const auto& access_mem = load_or_store ? ins->load_memory : ins->store_memmory;

    for (const auto& mem_addr_val : access_mem) {
      access_mem_addrs.push_back(std::get<0>(mem_addr_val));
    }
  }

  return access_mem_addrs;
}


auto split_trace_into_chunks (const p_instructions_t& trace) -> std::vector<p_instructions_t>
{
  auto ins_chunks = std::vector<p_instructions_t>{};

  auto begin_iter = std::begin(trace);
  auto last_iter = std::end(trace); --last_iter;

  for (auto ins_iter = std::begin(trace); ins_iter != std::end(trace); ++ins_iter) {
    if ((*ins_iter)->is_uncond_branch) {
//      tfm::printfln("%s", (*ins_iter)->disassemble);
      tfm::printfln("chunk size: %d instructions", ins_iter - begin_iter + 1);
      ins_chunks.push_back(p_instructions_t(begin_iter, ins_iter + 1));
      begin_iter = ins_iter; ++begin_iter;
    }
    else if (ins_iter == last_iter) {
      tfm::printfln("chunk size: %d instructions (last)", std::end(trace) - begin_iter);
      ins_chunks.push_back(p_instructions_t(begin_iter, std::end(trace)));
    }
  }

  return ins_chunks;
}


auto split_trace_into_chunks (const p_instructions_t& trace, ADDRINT start_addr) -> std::vector<p_instructions_t>
{
  auto ins_chunks = std::vector<p_instructions_t>{};

  auto begin_iter = std::begin(trace);
  auto end_iter = std::end(trace);
  auto begin_chunk_iter = end_iter;

  auto last_iter = end_iter; --last_iter;

  for (auto ins_iter = begin_iter; ins_iter != end_iter; ++ins_iter) {
    if ((*ins_iter)->address == start_addr) {
      if (begin_chunk_iter != end_iter) {
        ins_chunks.push_back(p_instructions_t(begin_chunk_iter, ins_iter));
      }

      begin_chunk_iter = ins_iter;
    }
    else if (ins_iter == last_iter) {
      if (begin_chunk_iter != end_iter) {
        ins_chunks.push_back(p_instructions_t(begin_chunk_iter, last_iter));
      }
    }
  }

  return ins_chunks;
}


static auto extract_memory_access_chunks (p_instructions_t trace) -> std::vector<p_chunk_mem_access_t>
{
  auto mem_access_chunks = std::vector<p_chunk_mem_access_t>{};

  auto ins_chunks = split_trace_into_chunks(trace);
  for (auto chunk : ins_chunks) {
    auto load_addresses = get_memory_access_addresses<MEM_LOAD>(chunk);
    auto store_addresses = get_memory_access_addresses<MEM_STORE>(chunk);

    auto new_chunk_mem = std::make_shared<chunk_mem_access_t>(load_addresses, store_addresses);
    mem_access_chunks.push_back(new_chunk_mem);
  }

  return mem_access_chunks;
}


using address_set_pair_t = std::pair< std::set<ADDRINT>, std::set<ADDRINT> >;
static auto get_memory_io_of_chunk (const p_instructions_t& chunk) -> address_set_pair_t
{
  auto input_addrs = std::set<ADDRINT>{};
  auto output_addrs = std::set<ADDRINT>{};

  for (const auto& ins : chunk) {
    for (auto load_addr_val : ins->load_memory) {
      auto load_addr = std::get<0>(load_addr_val);
      if (output_addrs.find(load_addr) == std::end(output_addrs)) {
        input_addrs.insert(load_addr);
      }
    }

    for (auto store_addr_val : ins->store_memmory) {
      auto store_addr = std::get<0>(store_addr_val);
      output_addrs.insert(store_addr);
    }
  }

  return std::make_pair(input_addrs, output_addrs);
}


static auto get_static_memory_access_addresses_of_chunk (const p_instructions_t& chunk) -> address_set_pair_t
{
  auto load_addrs = std::set<ADDRINT>{};
  auto store_addrs = std::set<ADDRINT>{};

  for (const auto& ins : chunk) {
    for (auto addr : ins->static_load_addresses) {
      load_addrs.insert(addr);
    }

    for (auto addr : ins->static_store_addresses) {
      store_addrs.insert(addr);
    }
  }

  return std::make_pair(load_addrs, store_addrs);
}


static auto get_dynamic_memory_access_addresses_of_chunk (const p_instructions_t& chunk) -> address_set_pair_t
{
  auto load_addrs = std::set<ADDRINT>{0};
  auto store_addrs = std::set<ADDRINT>{0};

  for (const auto& ins : chunk) {
    auto ins_load_mem = ins->load_memory;
    if (ins_load_mem.size() > 0) {
      auto load_mem_addr = std::get<0>(*(std::begin(ins_load_mem)));
      for (auto idx = uint32_t{0}; idx < ins->load_memory_size; ++idx) {
        load_addrs.insert(load_mem_addr + idx);
      }
    }

    auto ins_store_mem = ins->store_memmory;
    if (ins_store_mem.size() > 0) {
      auto store_mem_addr = std::get<0>(*(std::begin(ins_store_mem)));
      for (auto idx = uint32_t{0}; idx < ins->store_memory_size; ++idx) {
        load_addrs.insert(store_mem_addr + idx);
      }
    }
  }

  return std::make_pair(load_addrs, store_addrs);
}


static auto update_memory_state_of_chunk (const p_instructions_t& chunk, std::map<ADDRINT, uint8_t>& mem_state) -> void
{
  auto update_state = [&](ADDRINT mem_addr, ADDRINT mem_val, uint8_t mem_size) -> void
  {
    uint8_t val_b[4];

    val_b[0] = mem_val & 0xff;
    val_b[1] = (mem_val >> 8) & 0xff;
    val_b[2] = (mem_val >> 16) & 0xff;
    val_b[3] = (mem_val >> 24) & 0xff;

    for (auto idx = uint8_t{0}; idx < mem_size; ++idx) {
      if (mem_state.find(mem_addr + idx) != std::end(mem_state)) {
        mem_state[mem_addr + idx] = val_b[idx];
      }
    }
    return;
  };

  for (const auto& ins : chunk) {
    auto load_mem_size = ins->load_memory_size;
    if (load_mem_size > 0) {
      auto load_addr = std::get<0>(*(ins->load_memory.begin()));
      auto load_val = std::get<1>(*(ins->load_memory.begin()));

      update_state(load_addr, load_val, load_mem_size);
    }

    auto store_mem_size = ins->store_memory_size;
    if (store_mem_size > 0) {
      auto store_addr = std::get<0>(*(ins->store_memmory.begin()));
      auto store_val = std::get<1>(*(ins->store_memmory.begin()));

      update_state(store_addr, store_val, store_mem_size);
    }
  }
}


static auto init_memory_state (const std::set<ADDRINT>& addresses) -> std::map<ADDRINT, uint8_t>
{
  auto mem_state = std::map<ADDRINT, uint8_t>{};
  for (auto addr : addresses) {
    mem_state[addr] = 0x0;
  }
  return mem_state;
}


static auto get_static_memory_state_of_chunk (const p_instructions_t& chunk) -> std::map<ADDRINT, uint8_t>
{
  auto static_addrs_io = get_static_memory_access_addresses_of_chunk(chunk);
  auto addrs = std::get<0>(static_addrs_io);
  addrs.insert(std::get<1>(static_addrs_io).begin(), std::get<1>(static_addrs_io).end());

  auto mem_state = init_memory_state(addrs);
  update_memory_state_of_chunk(chunk, mem_state);

  return mem_state;
}


static auto get_dynamic_memory_state_of_chunk (const p_instructions_t& chunk) -> std::map<ADDRINT, uint8_t>
{
  auto dynamic_addrs_io = get_dynamic_memory_access_addresses_of_chunk(chunk);
  auto addrs = std::get<0>(dynamic_addrs_io);
  addrs.insert(std::get<1>(dynamic_addrs_io).begin(), std::get<1>(dynamic_addrs_io).end());

  auto mem_state = init_memory_state(addrs);
  update_memory_state_of_chunk(chunk, mem_state);

  return mem_state;
}


static auto get_chunk_index_sequence (const std::vector<p_chunk_mem_access_t>& chunks) -> std::vector<uint32_t>
{
  auto chunk_idx = uint32_t{0};
  auto chunk_idx_seq = std::vector<uint32_t>{};
  auto chunk_idx_pairs = chunk_index_pairs_t{};

  auto const begin_chunk_iter = std::begin(chunks);
  auto const end_chunk_iter = std::end(chunks);

  for (auto chunk_iter = begin_chunk_iter; chunk_iter != end_chunk_iter; ++chunk_iter) {
    auto idx = std::numeric_limits<uint32_t>::max();

    for (const auto& chunk_idx : chunk_idx_pairs) {
      if (is_equal(*chunk_iter, std::get<0>(chunk_idx))) {
        idx = std::get<1>(chunk_idx);
        break;
      }
    }

    if (idx == std::numeric_limits<uint32_t>::max()) {
      idx = chunk_idx;
      ++chunk_idx;
    }

    chunk_idx_pairs.push_back(std::make_pair(*chunk_iter, idx));
  }

  std::transform(std::begin(chunk_idx_pairs),
                 std::end(chunk_idx_pairs), std::back_inserter(chunk_idx_seq),
                 [&](decltype(chunk_idx_pairs)::reference chunk_idx) { return std::get<1>(chunk_idx); });

  tfm::printfln("chunk sequence size: %d", chunk_idx_seq.size());
  return chunk_idx_seq;
}


/* ===================================== exported functions ===================================== */

auto save_memory_access_to_file (const std::string& filename) -> void
{
  try {
    std::ofstream output_file(filename.c_str(), std::ofstream::trunc);
    if (!output_file) throw std::logic_error("cannot open output file");

    auto ins_chunks = split_trace_into_chunks(trace);
    for (auto chunk : ins_chunks) {
      tfm::format(output_file, "=====\n");

      for (const auto& ins : chunk) {
        tfm::format(output_file, "%-40s", ins->disassemble);

        if (ins->load_memory.size() == 0) {
          tfm::format(output_file, "%19s", "");
        }
        else {
          for (const auto& addr_val : ins->load_memory) {
            tfm::format(output_file, "0x%7x:0x%-7x", std::get<0>(addr_val), std::get<1>(addr_val));
          }
        }

        if (ins->store_memmory.size() == 0) {
          tfm::format(output_file, "   %19s", "");
        }
        else {
          for (const auto& addr_val : ins->store_memmory) {
            tfm::format(output_file, "   0x%7x:0x%-7x", std::get<0>(addr_val), std::get<1>(addr_val));
          }
        }

        tfm::format(output_file, "\n");
      }

//      auto load_addresses = get_memory_access_addresses<MEM_LOAD>(chunk);
//      auto store_addresses = get_memory_access_addresses<MEM_STORE>(chunk);


//      tfm::format(output_file, "lod: ");
//      for (auto load_addr : load_addresses) {
//        tfm::format(output_file, "0x%x ", load_addr);
//      }

//      tfm::format(output_file, "\nsto: ");
//      for (auto store_addr : store_addresses) {
//        tfm::format(output_file, "0x%x ", store_addr);
//      }

      tfm::format(output_file, "\n");
    }

    output_file.close();
    tfm::printfln("output file: %s", filename);
  }
  catch (const std::exception& expt) {
    tfm::printfln("%s", expt.what());
  }

  return;
}


auto save_chunk_sequence_to_file (const std::string& filename) -> void
{
  try {
    std::ofstream output_file(filename.c_str(), std::ofstream::trunc);
    if (!output_file) throw std::logic_error("cannot open output file");

    auto chunks = extract_memory_access_chunks(trace);
    auto chunk_idx_seq = get_chunk_index_sequence(chunks);

    for (auto chunk_idx : chunk_idx_seq) {
      tfm::format(output_file, "%d ", chunk_idx);
    }

    output_file.close();
    tfm::printfln("output file: %s", filename);
  }
  catch (const std::exception& expt) {
    tfm::printfln("%s", expt.what());
  }

  return;
}


auto save_chunks_io_to_file (const std::string& filename) -> void
{
  try {
    std::ofstream output_file(filename.c_str(), std::ofstream::trunc);
    if (!output_file) throw std::logic_error("cannot open output file");

    auto ins_chunks = split_trace_into_chunks(trace);

    for (const auto& chunk : ins_chunks) {
      auto io_addrs = get_memory_io_of_chunk(chunk);
      auto static_io_addrs = get_static_memory_access_addresses_of_chunk(chunk);

      auto input_addrs = std::get<0>(io_addrs);
      auto output_addrs = std::get<1>(io_addrs);

      tfm::format(output_file, "=====\n");

      tfm::format(output_file, "I: ");
      for (auto addr : input_addrs) {
        tfm::format(output_file, "0x%x ", addr);
      }
      tfm::format(output_file, "\n");

      tfm::format(output_file, "O: ");
      for (auto addr : output_addrs) {
        tfm::format(output_file, "0x%x ", addr);
      }
      tfm::format(output_file, "\n");
    }

    output_file.close();
    tfm::printfln("output file: %s", filename);
  }
  catch (const std::exception& expt) {
    tfm::printfln("%s", expt.what());
  }

  return;
}


auto save_memory_state_to_file (const std::string& filename) -> void
{
  try {
    auto ins_chunks = split_trace_into_chunks(trace);

    auto chunk_idx = uint32_t{0};
    for (const auto& chunk : ins_chunks) {
      auto chunk_idx_str = std::to_string(chunk_idx);
      auto chunk_filename = filename + chunk_idx_str;

      std::ofstream output_file(chunk_filename.c_str(), std::ofstream::trunc);
      if (!output_file) throw std::logic_error("cannot open output file");

      auto chunk_mem_state = get_static_memory_state_of_chunk(chunk);
//      auto chunk_mem_state = get_dynamic_memory_state_of_chunk(chunk);

      for (const auto& addr_val : chunk_mem_state) {
        tfm::format(output_file, "0x%x 0x%x\n", std::get<0>(addr_val), std::get<1>(addr_val));
      }

      output_file.close();
      tfm::printfln("output file: %s", chunk_filename);

      ++chunk_idx;
    }
  }
  catch (const std::exception& expt) {
    tfm::printfln("%s", expt.what());
  }

  return;
}
