//
// Created by 28116 on 2024/7/22.
//

#ifndef PWATCH_C_DISASM_H
#define PWATCH_C_DISASM_H

#include "capstone/capstone.h"
#include <vector>
#include <string>
#include <sstream>
#include <list>
#include <errno.h>
#include <iostream>

class disasm {

    csh handle;
public:
    disasm(){
        if (cs_open(CS_ARCH_AARCH64, CS_MODE_ARM, &handle) != CS_ERR_OK) {
            std::cerr << "ERROR: Failed to initialize disassembler" << std::endl;

        }
        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    }
    ~disasm(){
        cs_close(&handle);
    }

    //根据地址读取字节码进行反汇编
    std::string disasm_code(uint64_t addr,std::vector<uint8_t>& code) ;
};


#endif //PWATCH_C_DISASM_H
