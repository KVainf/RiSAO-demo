#include "pspin-ir.hpp"
#include <queue>

namespace PSPINIR {
    void print_pspin_prog_driver(const Program &prog, std::ostream &os) {
        
    }

    void print_pspin_prog_headerfile(const Program &prog, std::ostream &os) {
        os << " /* -*- macros and pragmas -*-  */ " << std::endl;
        os << "#pragma once" << std::endl;
    }

    void print_pspin_prog_handler(const Program &prog, std::ostream &os) {
        /* macros and pragmas */
        os << " /* -*- macros and pragmas -*-  */ " << std::endl;
        os << "#ifndef HOST" << std::endl;
        os << "#include <handler.h>" << std::endl;
        os << "#else" << std::endl;
        os << "#include <handler_profile.h>" << std::endl;
        os << "#endif" << std::endl;

        /* header files */
        os << " /* -*- header files -*-  */ " << std::endl;
        os << "#include <packets.h> " << std::endl;
        os << "#include <spin_dma.h>" << std::endl;
        os << "#include <spin_conf.h>" << std::endl;
        


        
    }
}