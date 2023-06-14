
Segments = [
        # ["eflash-0", 0x3F400000, 0x3F7FFFFF, 4], # already mapped: .flash.rodata
        # ["eram",       0x3F800000, 0x3FBFFFFF, 6], # large and low value for me
        ["peripheral", 0x3FF00000, 0x3FF7FFFF, 6], # memory-mapped IO
        ["irom1",      0x3FF90000, 0x3FF9FFFF, 4], # map manually
        # ["sram2",    0x3FFAE000, 0x3FFDFFFF, 6], # already mapped: .dram0.data
        ["sram1-0",    0x3FFE0000, 0x3FFFFFFF, 6], # map manually
        ["irom0",      0x40000000, 0x4005FFFF, 5], # map manually
        # ["sram0",    0x40070000, 0x4009FFFF, 7], # already mapped: .iram.vectors
        ["sram1-1",    0x400A0000, 0x400BFFFF, 7], # map manually
        # ["eflash-1", 0x400C2000, 0x40BFFFFF, 5], # already mapped: .flash.text is a subset of this
        ]

def loadBinaryFile(segment):
    name,start,end,perm = segment
    filename = name + ".bin"
    # load segment
    flags = ida_loader.NEF_SEGS
    if start >= 0x40000000: 
        flags |= ida_loader.NEF_CODE
    li = ida_diskio.open_linput(filename, False)
    if li:
        ida_loader.load_binary_file(filename, li, flags, 0, 0, start, 0)
    else:
        print("Warning: Could not load "+filename)
        return False
    # fix segment attributes
    seg = ida_segment.getseg(start)
    if seg:
        if start >= 0x40000000: 
            seg.align = 5 # dword
            ida_segment.set_segm_class(seg, "CODE", SEG_CODE)
        else:
            seg.align = 1 # byte
            ida_segment.set_segm_class(seg, "DATA", SEG_DATA)
        seg.perm = perm
        ida_segment.set_segm_name(seg, "."+name, 0)
    else:
        print("Warning: Segment "+name+" not created.")
        return False
    return True

for segment in Segments:
    if segment[0] == "peripheral":
        name,start,end,perm = segment
        ida_segment.add_segm(0, start, end, "."+name, "DATA", SEG_DATA)
        seg = ida_segment.getseg(start)
        seg.perm = 6
        seg.align = 6 # 4KB
    else:
        loadBinaryFile(segment)

