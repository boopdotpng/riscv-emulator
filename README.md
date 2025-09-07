# riscv-emulator
The eventual goal is to write a simple RISC-V core on an FPGA (i have an arty a7 100t). I wrote a Python emulator for a RISC-V core that shows how the base instructions work (RV32UI-p-*). 

## setup instructions
You need to set up the [risc-v-tests](https://github.com/riscv-software-src/riscv-tests) repository. Follow the instructions in their README. The python program just loads each ELF, maps the PT_LOAD segments to virtual memory, then executes the program line by line. 
