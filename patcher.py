
# OPAQUE PREDICATES DETECTOR & PATCHER



##------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ 

# NOTES


# Usage:
# python3 patcher.py ../samples/opaque_predicates 0x400546


# Debugging
"""
import ipdb
ipdb.set_trace()        - to set breakpoint
<class/function>?       - get information about class or function
"""


# References
"""
_Elf file Format
https://refspecs.linuxbase.org/elf/gabi4+/ch4.eheader.html
https://refspecs.linuxbase.org/elf/gabi4+/ch5.pheader.html
https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
"""


# Readelf (for reference)
"""
readelf - h <file>

ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x400450
  Start of program headers:          64 (bytes into file)
  Start of section headers:          53512 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         8
  Size of section headers:           64 (bytes)
  Number of section headers:         30
  Section header string table index: 27
"""


##------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ 

# IMPORTS


# Container = parsed binary file
# Machine = architecure of the binary
# LocationDB = maps addresses / offsets to h.r. labels/symb
# DiGraph = used for control flow graph creation
# mn_x86 = for parsing x86 asm

#from miasm.loader.elf import Ehdr, Phdr, PT_LOAD                                                       # elf file specific

# Elftools
from elftools.elf.elffile import ELFFile                                                                # alternative to miasms implementation
from elftools.elf.segments import Segment

# Miasm
from miasm.analysis.binary import Container, ContainerELF, ContainerPE
from miasm.expression.expression import ExprInt                                                         # used for assembly expressions
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB
from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.ir.translators.z3_ir import TranslatorZ3

# Miscellaneous
from z3 import *
import sys
import ipdb


##------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ 

# GLOBALS

## VARS
patches = {}                                                                                            # python dic: file_offset -> byte value


## PARSE ARGS
if len(sys.argv) != 3:
    print(f"[*] Syntax: {sys.argv[0]} <file> <address>")
    exit()
file_path = sys.argv[1]
func_addr = int(sys.argv[2], 16)


## MIASM

# symbol table
loc_db = LocationDB()                                                                                   # used to keep track of all disassembled locations, basic block labels

# open the binary for analysis
cont = Container.from_stream(open(file_path, "rb"), loc_db)



# binary data stream
# used for accessing and manipulating raw binary data
b_stream = cont.bin_stream



# cpu abstraction
machine = Machine(cont.arch)                                                                            # defines for which architecure the input binary was created for
#print(cont.arch)


# initialize disassemble engine
mdis = machine.dis_engine(cont.bin_stream, loc_db=loc_db)                                               # add location of the binary and location of symbol table


# disassemble a basic block
#block = mdis.dis_block(func_addr)  # debug only
#print(block)     # debug only

# disassemble multiple blocks
asm_cfg = mdis.dis_multiblock(func_addr)                                                                # dissassemble function at given address
len(asm_cfg.blocks)     # print number of basicblocks


# initialize intermediate representation
ira = machine.lifter_model_call(mdis.loc_db)


# ASM_CFG -> IRA_CFG
# creation of intermedtiate representation control flow graph
ir_cfg = ira.new_ircfg_from_asmcfg(asm_cfg)




##------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ 

# HELPER FUNCTIONS


"""
Check if a given expression is an opque predicate
"""
def check_opaque(ir_expr, ir_src1, ir_src2):
    solver1 = Solver()
    solver2 = Solver()
    translator = TranslatorZ3()
    
    # Translate Miasm expressions to Z3
    expr_z3 = translator.from_expr(ir_expr)
    src1_z3 = translator.from_expr(ir_src1)
    src2_z3 = translator.from_expr(ir_src2)

    # Model the conditional behavior
    #sat + unsat --> opaque
    #unsat + sat --> opaque
    #sat + sat --> impossible
    #unsat + unsat --> impossible
    solver1.add(expr_z3 == src1_z3)
    solver2.add(expr_z3 == src2_z3)

    
    sat1 = solver1.check()
    sat2 = solver2.check()

    if (sat1 == sat and sat2 == unsat):              # always true, jump is taken
        return "always_true"
    elif (sat1 == unsat and sat2 == sat):            # always false, jump is never taken
        return "always_false"
    else:
        return "not opaque"                          # not an opaque predicate



# unused implementation to read elf file via miasm
"""
Elf file compatible virt2off function
"""
"""
def virt2off_elf(v_addr):
    #ipdb.set_trace()           
    word_s = 8                                                                                      # 8 bytes for 64-bit, 4 for 32-bit elf binary
    endianess = "Iend_LE"
    # get elf header structure
    elf_header = Ehdr(endianess, word_s, data)                                                      # little endian, wordsize elf64, binary data
    offset_ph = elf_header.phoff                                                                    # start of the program headers, elf has multiple ones
    
    # 2do: phnum is zero!
    # print(elf_header.phnum, elf_header.phoff, elf_header.phentsize)
    for i in range(elf_header.phnum):
        prog_header_bytes = data[offset_ph : offset_ph + elf_header.phentsize]                      # bytes of one program header   
        prog_header = Phdr(endianess, word_s, prog_header_bytes)                                    # little endian, wordsize elf64, program header data
        offset_ph += elf_header.phentsize                                                           # add size of program header, iterate through program headers
        # ignore sections which can not be loaded
        if prog_header.p_type != PT_LOAD:
            continue
        seg_start = prog_header.p_vaddr                                                             # start of the section in v memory
        #seg_end   = seg_start + prog_header.p_memsz                                                # end of the section in v memory
        seg_end = seg_start + prog_header.p_filesz                                                  # p_filesz = data only which resides on disc

        if seg_start <= v_addr < seg_end:
        #    return prog_header.p_offset + (v_addr - seg_start)
            # Ensure offset is inside file.
            file_size = len(data)
            foff = prog_header.p_offset + (v_addr - seg_start)                                      # seems to be correct according to the input by tim

            if foff >= file_size:
                print(f"[Error] VA {hex(v_addr)} maps past end of file: offset={hex(foff)}, file={hex(file_size)}")
                return -1
            return foff
    print(f"[Error] VA {hex(v_addr)} not inside any PT_LOAD segment")
    return -1
"""



"""
Custom virt2off implementation for ELF files, finds the file address of a given virtual address
"""
def virt2off_elf(v_addr):
    elf_file = ELFFile(open(file_path, "rb"))                                                       # open elf file using elftools
    # print(elf_file.header)

    for seg in elf_file.iter_segments():
        # Only consider loadable segments
        if seg['p_type'] != 'PT_LOAD':
            continue

        seg_start = seg['p_vaddr']                                                                  # get start of section in virt memory
        seg_end = seg_start + seg['p_filesz']                                                       # get end of segment, start + bytes in file

        if seg_start <= v_addr < seg_end:
            file_off = seg['p_offset'] + (v_addr - seg_start)
            # Ensure offset is within file
            if file_off >= elf_file.stream.seek(0, 2):                                              # seek from beginning to end of file
                print(f"[Error] VA {hex(v_addr)} maps past end of file")
                return -1
            return file_off

    print(f"[Error] VA {hex(v_addr)} not inside any PT_LOAD segment")
    return -1



"""
Patch a conditional jump (always true opaque) into an unconditional JMP.
"""
def patch_jmp(jmp_instr):
    # machine code instruction sizes x86-64
    # depending on arch this may vary
    JMP = 1
    REL32 = 4
     
   # Convert virtual address to file offset
    if isinstance(cont, ContainerPE):
        offset = b_stream.virt2off(jmp_instr.offset)
    elif isinstance(cont, ContainerELF):
        offset = virt2off_elf(jmp_instr.offset)
    else:
        print("[Error]: Unknown binary type")
        return -1

    if offset is None or offset < 0:
        #ipdb.set_trace()
        print(f"[Error]: Virtual adress {hex(jmp_instr.offset)} could not be converted into file offset")
        return -1

    # Compute relative offset for JMP rel32
    # jump displacement is added to the address immediately after the jump instruction (!)
    jmp_target = loc_db.get_location_offset(jmp_instr.args[0].loc_key)

    #ipdb.set_trace()

    rel32 = jmp_target - (jmp_instr.offset + (JMP + REL32))                                         # position of REL32 offset in new instruction
    rel32_bytes = rel32.to_bytes(REL32, byteorder='little', signed=True)                            # convert integer offset into machine bytecode, rel offset can be negative

    # Create JMP instruction bytes
    new_instr = b'\xE9' + rel32_bytes                                                               # x86 conversion

    # Build patch dictionary
    for i, b in enumerate(new_instr):
        patches[offset + i] = b

    # If original instruction was longer than 5 bytes, pad the rest with NOPs
    for i in range(len(jmp_instr.b) - len(new_instr)):
        patches[offset + len(new_instr) + i] = 0x90                                                 # length of new instruction


    return 0


"""
Patch a any jump (always false opaque) into a NOP.
"""
def patch_nop(jmp_instr):                       # not raw address, needs .b attribute
    # Convert virtual address to file offset
    if isinstance(cont, ContainerPE):
        offset = b_stream.virt2off(jmp_instr.offset)
    elif isinstance(cont, ContainerELF):
        offset = virt2off_elf(jmp_instr.offset)
    else:
        print("[Error]: Unknown binary type")
        return -1

    if offset is None or offset < 0:
        #ipdb.set_trace()
        print(f"[Error]: Virtual adress {hex(jmp_instr.offset)} could not be converted into file offset")
        return -1

    # Patch all bytes of that instruction
    for i in range(len(jmp_instr.b)):
        patches[offset + i] = 0x90



"""
Apply patches to original binary and save binary as new file
"""
def save_binary(file_path, out_path, patches):
    # Read raw bytes from file stream
    with open(file_path, 'rb') as f:
        raw = bytearray(f.read())
        # Apply each patch
        for off, val in patches.items():
            if 0 <= off < len(raw):
                raw[off] = val
            else:
                print(f"[Error]: Invalid Offset at {hex(off)}")
                return -1
    # Write to new file
    open(out_path, 'wb').write(raw)
    return 0




##------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ 

# MAIN

def main():
    for block in asm_cfg.blocks:                                                                # iterate over all basic blocks inside the function

        # address of first basic block in function
        #print(block.lines[0]) # debug
        basic_block_start = block.lines[0].offset                                               # .offset -> virtual address of instruction during runtime
        jmp_instr = block.lines[-1]                                                             # get last instruction containing conditional jump

        # check if still conditional after SE
        is_cond_cfg = ir_cfg.get_block(basic_block_start).dst.is_cond()                         # check if conditional exists before SB

        # init symbolic execution engine
        symb_eng = SymbolicExecutionEngine(ira)

        # symbolically execute block at given address
        ir_expr = symb_eng.run_block_at(ir_cfg, basic_block_start)                              # large miasm expression, src1 and src2 contained
        
        
        # patching procedure
        if ir_expr.is_cond():
            if hasattr(ir_expr, "src1") and hasattr(ir_expr, "src2"):                           # ensure expr is ExprOp
        
                # compare IR with ASM, swap if necessary
                ir_src1 = int(ir_expr.src1)
                ir_src2 = int(ir_expr.src2)
                asm_src = loc_db.get_location_offset(jmp_instr.args[0].loc_key)

                if ir_src1 != asm_src:
                    ir_src1, ir_src2 = ir_src2, ir_src1

                # always true: jump is always taken --> patch with jmp
                if (check_opaque(ir_expr, ExprInt(ir_src1,64), ExprInt(ir_src2,64))) == "always_true":
                    patch_jmp(basic_block_start, jmp_instr)  # raw assembly address

                # always false: jump is never taken --> patch with nop
                elif (check_opaque(ir_expr, ExprInt(ir_src1,64), ExprInt(ir_src2,64))) == "always_false":
                    patch_nop(jmp_instr) # jump target

        # check for mismatch between IR and ASM
        # if symbolic execution already solved the cond, it is definately an opaque predicate
        elif ir_expr.is_cond() != is_cond_cfg:
            #ipdb.set_trace()
            
            # get IR destination before SB
            full_expr = ir_cfg.get_block(basic_block_start).dst # ExprCond(ExprOp('CC_EQ', ExprId('zf', 1)), ExprLoc(<LocKey 30>, 64), ExprLoc(<LocKey 33>, 64))
            true_loc_expr  = full_expr.src1
            false_loc_expr = full_expr.src2

            # Extract LocKey
            true_key  = true_loc_expr.loc_key
            false_key = false_loc_expr.loc_key

            # Convert LocKey to original addresses
            true_addr  = loc_db.get_location_offset(true_key)   # address of first destination as int
            false_addr = loc_db.get_location_offset(false_key)  # address of second destination as int

            # get IR destination after SB
            sym_exec_dst = ir_expr.arg                          # destination in int after SB, should be equal to src1 or src2

            # always true opaque
            if true_addr == sym_exec_dst:
                patch_jmp(jmp_instr)                            # unresolved jmp_instr is passed

            # always false opaque
            elif false_addr == sym_exec_dst:
                patch_nop(jmp_instr)
            else:
                print(f"[Error]: No common address before and after SB:\n\tBefore SB: {hex(sym_exec_dst)}\n\tAfter SB: {hex(true_addr)}, {hex(false_addr)}")

        else:
           continue

    out_path = "./patched"                                                                          # save file path
    save_binary(file_path, out_path, patches)




##------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ 

# SCRIPT ENTRY POINT

if __name__ == "__main__":
    main()
