ea = 0x0
counter = 0
failures = 0
print("STARTING STARTING STARTING")
while True:
    ea = ida_bytes.find_byte(ea+1,0xffffffff, 0x36, 0)
    if ea == BADADDR:
        break
    buf = get_bytes(ea,3)
    if (buf[0]&0xFF) != 0x36 or (buf[1]&0x0F) != 0x01 or (buf[2]&0xF0) != 0x00:
        continue
    if buf == b'\x36\x01\x00':
        continue # would be `entry a1,0`, which doesn't happen
    if ida_funcs.get_func(ea):
        continue # already a function here
    mnem = ida_ua.ua_mnem(ea) or ida_ua.ua_mnem(ea-1) or ida_ua.ua_mnem(ea-2)
    if mnem and mnem != 'entry':
        continue
    if is_data(ida_bytes.get_flags(get_item_head(ea))):
        del_items(ea)
    r = add_func(ea)
    if r:
        counter += 1
    else:
        failures += 1
    print("Creating: "+hex(ea)+" => "+str(r))
print("Created %d/%d new functions."%(counter,counter+failures))

