#include "hilvl-ir.hpp"
#include "hir-common-pass.hpp"
#include "llvm-load.hpp"
#include "hir-pktop.hpp"
#include "hir-stateop.hpp"
#include "hir-pspin.hpp"
#include <iostream>

int main(int argc, char *argv[]) {
    LLVMStore store;
    store.load_directory("../../click-llvm-ir/ele_ll/tcpudp");
    store.load_directory("../../click-llvm-ir/lib_ll");

    auto m = std::make_shared<HIR::Module>();
    // auto ele = std::make_shared<HIR::Element>(*m, store, "MyIPRewriter");

    auto ele = std::make_shared<HIR::Element>(*m, store, argv[1]);

    element_function_inline(*ele);
    replace_packet_access_op(*ele, CommonHdr::default_layout);
    remove_unused_phi_entry(*ele->entry());

    split_stateptr_branch(*ele);
    replace_vector_ops(*ele);
    replace_map_ops(*ele);
    replace_regular_struct_access(*ele->entry());
    replace_packet_meta_op(*ele);
    // remove_unused_ops(*ele);
    HIR::LabelInitFn init_fn = PSPINIR::pspin_initial_label;
    HIR::label(*ele, init_fn);

    // auto partition_result = PSPINIR::partition_hir(ele);
    auto partition_result = partition(*ele -> entry());
    
    
    return 0;
}
