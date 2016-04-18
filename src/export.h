#ifndef EXPORT_H
#define EXPORT_H

#include "type/instruction.h"

#include <string>

//auto split_trace_into_chunks           (const p_instructions_t& trace) -> std::vector<p_instructions_t>;

auto parse_instructions_from_file      (const std::string& filename)   -> const p_instructions_t&;
auto save_trace_to_file                (const std::string& filename)   -> void;
auto save_chunk_sequence_to_file       (const std::string& filename)   -> void;
auto save_chunks_io_to_file            (const std::string& filename)   -> void;
auto save_memory_access_to_file        (const std::string& filename)   -> void;
auto save_memory_state_to_file         (const std::string& filename)   -> void;
auto save_chunks_to_file               (const std::string& filename)   -> void;

template<bool cfg_or_tree>
auto construct_basic_block_graph       () -> void;
auto construct_basic_block_cfg = construct_basic_block_graph<true>;
auto construct_basic_block_tree = construct_basic_block_graph<false>;

template<bool cfg_or_tree>
auto save_basic_block_graph_to_dot_file (const std::string& filename)  -> void;
auto save_basic_block_cfg_to_dot_file = save_basic_block_graph_to_dot_file<true>;
auto save_basic_block_tree_to_dot_file = save_basic_block_graph_to_dot_file<false>;

auto add_trace_into_basic_block_cfg    (const p_instructions_t& trace) -> void;
auto add_trace_into_basic_block_tree   (const p_instructions_t& trace) -> void;

auto initialize_movf_identifiers       (uint32_t target, uint32_t branch) -> void;
auto construct_movf_basic_block_cfg    (const p_instructions_t& prog)  -> void;
auto save_movf_basic_block_cfg_to_file (const std::string& filename)   -> void;

#endif // EXPORT_H

