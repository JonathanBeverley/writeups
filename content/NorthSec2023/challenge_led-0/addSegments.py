
Segments = [
        ["irom0",      0x40000000, 0x4005FFFF, NEF_CODE, 5], # map manually
        ["irom1",      0x3FF90000, 0x3FF9FFFF, NEF_DATA, 4], # map manually
        # ["sram0",    0x40070000, 0x4009FFFF, NEF_CODE, 7], # already mapped: .iram.vectors
        ["sram1-0",    0x3FFE0000, 0x3FFFFFFF, NEF_DATA, 6], # map manually
        ["sram1-1",    0x400A0000, 0x400BFFFF, NEF_CODE, 7], # map manually
        # ["sram2",    0x3FFAE000, 0x3FFDFFFF, NEF_DATA, 6], # already mapped: .dram0.data
        ["peripheral", 0x3FF00000, 0x3FF7FFFF, NEF_DATA, 6], # memory-mapped IO
        # ["eflash-0", 0x3F400000, 0x3F7FFFFF, NEF_DATA, 4], # already mapped: .flash.rodata
        # ["eflash-1", 0x400C2000, 0x40BFFFFF, NEF_CODE, 5], # already mapped: .flash.text
        # ["eram",     0x3F800000, 0x3FBFFFFF, NEF_DATA, 6], # I'm not sure how to download this
        ]

for segment in Segments:
    if segment[0] == "peripheral":
        name,start,end,flags,perm = segment
        ida_segment.add_segm(0, start, end, "."+name, "DATA", SEG_DATA)
        seg = ida_segment.getseg(start)
        seg.perm = 6
        seg.align = 6 # 4KB
    else:
        loadBinaryFile(segment)

def loadBinaryFile(segment):
    name,start,end,flags,perm = segment
    filename = name + ".bin"
    # load segment
    flags |= NEF_SEGS
    li = ida_diskio.open_linput(filename, False)
    if li:
        ida_loader.load_binary_file(filename, li, flags, 0, 0, start, 0)
    else:
        print("Warning: Could not load "+filename)
        return False
    # fix segment attributes
    seg = ida_segment.getseg(start)
    if seg:
        if start < 0x40000000: 
            seg.align = 5 # dword
        else:
            seg.align = 1 # byte
        seg.perm = perm
        ida_segment.set_segm_name(seg, "."+name, 0)
    else:
        print("Warning: Segment "+name+" not created.")
        return False
    return True

