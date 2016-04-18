#include "export.h"
#include "tinyformat.h"

#include <stdexcept>
#include <cstring>
#include <ctime>


int main(int argc, char* argv[])
{
  auto starting_time = std::clock();

  try {
    if (argc < 4)
      throw std::logic_error("please run as: cfgrecon mode[trace/tree/cfg/movf] protobuf_trace_file(s) output_file(s)");

    if (strcmp(argv[1], "cfg") == 0 || strcmp(argv[1], "tree") == 0) {
      auto cfg_or_tree = true;
      if (strcmp(argv[1], "cfg") == 0) cfg_or_tree = true;
      else if (strcmp(argv[1], "tree") == 0) cfg_or_tree = false;

      auto add_trace_fun = cfg_or_tree ? add_trace_into_basic_block_cfg : add_trace_into_basic_block_tree;
      auto construct_fun = cfg_or_tree ? construct_basic_block_cfg : construct_basic_block_tree;
      auto save_to_file_fun = cfg_or_tree ? save_basic_block_cfg_to_dot_file : save_basic_block_tree_to_dot_file;

      auto trace_file_max_idx = argc - 1;
      for (auto idx = 2; idx < trace_file_max_idx; ++idx) {
        auto pb_trace_file = std::string(argv[idx]);

        auto trace = parse_instructions_from_file(pb_trace_file);

        add_trace_fun(trace);
      }

      construct_fun();

      auto bb_cfg_file = std::string(argv[argc - 1]);
      save_to_file_fun(bb_cfg_file);
    }
    else {
      if (strcmp(argv[1], "trace") == 0) {
        auto pb_trace_file = std::string(argv[2]);
        auto output_trace_file = std::string(argv[3]);

        parse_instructions_from_file(pb_trace_file);
  //      save_chunks_to_file (output_trace_file);
        save_trace_to_file(output_trace_file);

        if (argc > 4) {
  //        auto output_mem_access_file = std::string(argv[4]);
  //        save_memory_access_to_file(output_mem_access_file);
  //        save_chunk_sequence_to_file(output_mem_access_file);
  //        save_chunks_io_to_file(output_mem_access_file);
  //        save_memory_state_to_file(output_mem_access_file);
        }
      }
      else {
        if (strcmp(argv[1], "movf") != 0) throw std::logic_error("mode must be trace, tree, cfg, or movf");

        initialize_movf_identifiers(0x80e1cbc, 0x80d1c90);

        auto pb_trace_file = std::string(argv[2]);
        auto trace = parse_instructions_from_file(pb_trace_file);

        construct_movf_basic_block_cfg(trace);

        auto movf_bb_cfg_file = std::string(argv[argc - 1]);
        save_movf_basic_block_cfg_to_file(movf_bb_cfg_file);
      }
    }
  }
  catch (const std::exception& expt) {
    tfm::printfln("%s", expt.what());
  }

  auto ending_time = std::clock();
  tfm::printfln("\nelapsed time: %d secs", (ending_time - starting_time) / CLOCKS_PER_SEC);

  return 0;
}

