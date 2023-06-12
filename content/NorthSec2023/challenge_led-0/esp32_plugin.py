from ida_lines import COLOR_INSN, COLOR_MACRO
from ida_idp import CUSTOM_INSN_ITYPE, IDP_Hooks, ph_get_regnames, ph_get_id, PLFM_XTENSA
from ida_bytes import get_bytes
from ida_idaapi import plugin_t, PLUGIN_PROC, PLUGIN_HIDE, PLUGIN_SKIP, PLUGIN_KEEP
from ida_ua import o_void, o_near, o_displ, o_reg, o_imm, dt_dword, OOF_ADDR
from struct import unpack

DEBUG_PLUGIN = True

NEWINSN_COLOR = COLOR_MACRO if DEBUG_PLUGIN else COLOR_INSN

class NewInstructions:
    (
            NN_quou,
            NN_muluh,
            NN_nop,
            NN_quos,
            NN_s32c1i,
            NN_wur,
            NN_wsr,
            NN_rur,
            NN_rsr,
            NN_rotw,
            NN_mulsh,
            NN_xsr,
            NN_remu,
            NN_rems,
            NN_float,
            NN_wfr,
            NN_olt,
            NN_bf,
            NN_bt,
            NN_rfr,
            NN_ssi,
            NN_mul_s,
            NN_utrunc,
            NN_lsi,
            NN_add,
            NN_trunc,
            NN_ufloat,
            NN_ole,
            NN_mov,
            NN_ldip,
            NN_sdip,
            NN_sub,
            NN_msub,
            NN_sdi,
            NN_neg,
            NN_madd,
            NN_movsp,
            NN_div0,
            NN_nexp01,
            NN_const,
            NN_maddn,
            NN_mkdadj,
            NN_addexp,
            NN_addexpm,
            NN_divn,
            NN_abs,
            NN_ule,
    ) = range(CUSTOM_INSN_ITYPE, CUSTOM_INSN_ITYPE+47)

    lst = {
            NN_quou:"quou",
            NN_muluh:"muluh",
            NN_nop:"nop.n",
            NN_quos:"quos",
            NN_s32c1i:"s32c1i",
            NN_wur:"wur",
            NN_wsr:"wsr",
            NN_rur:"rur",
            NN_rsr:"rsr",
            NN_rotw:"rotw",
            NN_mulsh:"mulsh",
            NN_xsr:"xsr",
            NN_remu:"remu",
            NN_rems:"rems",
            NN_float:"float.s",
            NN_wfr:"wfr",
            NN_olt:"olt.s",
            NN_bf:"bf",
            NN_bt:"bt",
            NN_rfr:"rfr",
            NN_ssi:"ssi",
            NN_mul_s:"mul.s",
            NN_utrunc:"utrunc.s",
            NN_lsi:"lsi",
            NN_add:"add.s",
            NN_trunc:"trunc.s",
            NN_ufloat:"ufloat.s",
            NN_ole:"ole.s",
            NN_mov:"mov.s",
            NN_ldip:"ldip",
            NN_sdip:"sdip",
            NN_sub:"sub.s",
            NN_msub:"msub.s",
            NN_sdi:"sdi",
            NN_neg:"neg.s",
            NN_madd:"madd.s",
            NN_movsp:"movsp",
            NN_div0:"div0.s",
            NN_nexp01:"nexp01.s",
            NN_const:"const.s",
            NN_maddn:"maddn.s",
            NN_mkdadj:"mkdadj.s",
            NN_addexp:"addexp.s",
            NN_addexpm:"addexpm.s",
            NN_divn:"divn.s",
            NN_abs:"abs.s",
            NN_ule:"ule.s",
            }


    SpecialRegister = {
            0x00:"lbeg",
            0x01:"lend",
            0x02:"lcount",
            0x03:"sar",
            0x04:"br",
            0x05:"litbase",
            0x0c:"scompare1",
            0x10:"acclo",
            0x11:"acchi",
            0x20:"m0",
            0x21:"m1",
            0x22:"m2",
            0x23:"m3",
            0x48:"windowbase",
            0x49:"windowstart",
            0x53:"ptevaddr",
            0x59:"mmid",
            0x5a:"rasid",
            0x5b:"itlbcfg",
            0x5c:"dtlbcfg",
            0x60:"ibreakenable",
            0x61:"memctl",
            0x62:"cacheattr",
            0x63:"atomctl",
            0x68:"ddr",
            0x6a:"mepc",
            0x6b:"meps",
            0x6c:"mesave",
            0x6d:"mesr",
            0x6e:"mecr",
            0x6f:"mevaddr",
            0x80:"ibreaka0",
            0x81:"ibreaka1",
            0x90:"dbreaka0",
            0x91:"dbreaka1",
            0xa0:"dbreakc0",
            0xa1:"dbreakc1",
            0xb0:"configid0",
            0xb1:"epc1",
            0xb2:"epc2",
            0xb3:"epc3",
            0xb4:"epc4",
            0xb5:"epc5",
            0xb6:"epc6",
            0xb7:"epc7",
            0xc0:"depc",
            0xc2:"eps2",
            0xc3:"eps3",
            0xc4:"eps4",
            0xc5:"eps5",
            0xc6:"eps6",
            0xc7:"eps7",
            0xd1:"excsave1",
            0xd2:"excsave2",
            0xd3:"excsave3",
            0xd4:"excsave4",
            0xd5:"excsave5",
            0xd6:"excsave6",
            0xd7:"excsave7",
            0xe0:"cpenable",
            0xe1:"interrupt",
            0xe2:"intset",
            0xe3:"intclear",
            0xe4:"intenable",
            0xe6:"ps",
            0xe7:"vecbase",
            0xe8:"exccause",
            0xe9:"debugcause",
            0xea:"ccount",
            0xeb:"prid",
            0xec:"icount",
            0xed:"icountlevel",
            0xee:"excvaddr",
            0xf0:"ccompare0",
            0xf1:"ccompare1",
            0xf2:"ccompare2",
            0xf4:"misc0",
            0xf5:"misc1",
            0xf6:"misc2",
            0xf7:"misc3",
            }

    UserRegister = {
            0xe6:"expstate",
            0xe7:"threadptr",
            0xe8:"fcr",
            0xe9:"fsr",
            0xea:"f64r_lo",
            0xeb:"f64r_hi",
            0xec:"f64s",
            }

    FloatRegisterBase = 0x14
#--------------------------------------------------------------------------
class xtensa_idp_hook_t(IDP_Hooks):
    def __init__(self):
        IDP_Hooks.__init__(self)

    def sign_extend(self, value, bits):
        sign_bit = 1 << (bits - 1)
        return (value & (sign_bit - 1)) - (value & sign_bit)

    def decode_instruction(self, insn):
        buf = get_bytes(insn.ea, 2)

        if buf[1] == 0xF0 and buf[0] == 0x3D:
            insn.itype = NewInstructions.NN_nop
            insn.size = 2
            return 2

        buf += get_bytes(insn.ea+2, 1)
        #print("%08X bytes %X %X %X" % (insn.ea , buf[2] , buf[1] , buf[0]))

        if buf[2] == 0xA2 and (buf[0] & 0xF) == 0:
            insn.itype = NewInstructions.NN_muluh
            insn.size = 3
            insn.Op1.type = o_reg
            insn.Op1.reg = buf[1] >> 4
            insn.Op2.type = o_reg
            insn.Op2.reg = buf[1] & 0xF
            insn.Op3.type = o_reg
            insn.Op3.reg = buf[0] >> 4
            return 3

        if buf[2] == 0xB2 and (buf[0] & 0xF) == 0:
            insn.itype = NewInstructions.NN_mulsh
            insn.size = 3
            insn.Op1.type = o_reg
            insn.Op1.reg = buf[1] >> 4
            insn.Op2.type = o_reg
            insn.Op2.reg = buf[1] & 0xF
            insn.Op3.type = o_reg
            insn.Op3.reg = buf[0] >> 4
            return 3

        if buf[2] == 0xC2 and (buf[0] & 0xF) == 0:
            insn.itype = NewInstructions.NN_quou
            insn.size = 3
            insn.Op1.type = o_reg
            insn.Op1.reg = buf[1] >> 4
            insn.Op2.type = o_reg
            insn.Op2.reg = buf[1] & 0xF
            insn.Op3.type = o_reg
            insn.Op3.reg = buf[0] >> 4
            return 3

        if buf[2] == 0xD2 and (buf[0] & 0xF) == 0:
            insn.itype = NewInstructions.NN_quos
            insn.size = 3
            insn.Op1.type = o_reg
            insn.Op1.reg = buf[1] >> 4
            insn.Op2.type = o_reg
            insn.Op2.reg = buf[1] & 0xF
            insn.Op3.type = o_reg
            insn.Op3.reg = buf[0] >> 4
            return 3

        if buf[2] == 0xE2 and (buf[0] & 0xF) == 0:
            insn.itype = NewInstructions.NN_remu
            insn.size = 3
            insn.Op1.type = o_reg
            insn.Op1.reg = buf[1] >> 4
            insn.Op2.type = o_reg
            insn.Op2.reg = buf[1] & 0xF
            insn.Op3.type = o_reg
            insn.Op3.reg = buf[0] >> 4
            return 3

        if buf[2] == 0xF2 and (buf[0] & 0xF) == 0:
            insn.itype = NewInstructions.NN_rems
            insn.size = 3
            insn.Op1.type = o_reg
            insn.Op1.reg = buf[1] >> 4
            insn.Op2.type = o_reg
            insn.Op2.reg = buf[1] & 0xF
            insn.Op3.type = o_reg
            insn.Op3.reg = buf[0] >> 4
            return 3

        if (buf[1] & 0xF0) == 0xE0 and (buf[0] & 0xF) == 0x2:
            insn.itype = NewInstructions.NN_s32c1i
            insn.size = 3
            insn.Op1.type = o_reg
            insn.Op1.reg = buf[0] >> 4
            insn.Op2.type = o_reg
            insn.Op2.reg = buf[1] & 0xF
            insn.Op3.type = o_imm
            insn.Op3.value = buf[2] << 2
            return 3

        if buf[2] == 0x03 and (buf[0] & 0xF) == 0x0:
            insn.itype = NewInstructions.NN_rsr
            insn.size = 3
            insn.insnpref = buf[1]
            insn.Op1.type = o_reg
            insn.Op1.reg = buf[0] >> 4
            return 3

        if buf[2] == 0xe3 and (buf[0] & 0xF) == 0x0:
            insn.itype = NewInstructions.NN_rur
            insn.size = 3
            insn.insnpref = ((buf[1]&0xf)<<4) | (buf[0] >> 4)
            insn.Op1.type = o_reg
            insn.Op1.reg = buf[1] >> 4
            return 3

        if buf[2] == 0x13 and (buf[0] & 0xF) == 0x0:
            insn.itype = NewInstructions.NN_wsr
            insn.size = 3
            insn.insnpref = buf[1]
            insn.Op1.type = o_reg
            insn.Op1.reg = buf[0] >> 4
            return 3

        if buf[2] == 0xf3 and (buf[0] & 0xF) == 0x0:
            insn.itype = NewInstructions.NN_wur
            insn.size = 3
            insn.insnpref = buf[1]
            insn.Op1.type = o_reg
            insn.Op1.reg = buf[0] >> 4
            return 3

        if buf[2] == 0x61 and (buf[0] & 0xF) == 0x0:
            insn.itype = NewInstructions.NN_xsr
            insn.size = 3
            insn.insnpref = buf[1]
            insn.Op1.type = o_reg
            insn.Op1.reg = buf[0] >> 4
            return 3

        if buf[2] == 0x40 and buf[1] == 0x80 and (buf[0] & 0xF) == 0x0:
            insn.itype = NewInstructions.NN_rotw
            insn.size = 3
            insn.Op1.type = o_imm
            insn.Op1.value = self.sign_extend(buf[0] >> 4,4)
            return 3

        if buf[2] == 0x00 and (buf[1] >> 4) == 0x1 and (buf[0] & 0xF) == 0x0:
            insn.itype = NewInstructions.NN_movsp
            insn.size = 3
            insn.Op1.type = o_reg
            insn.Op1.reg = (buf[1] >> 4)
            insn.Op2.type = o_reg
            insn.Op2.reg = (buf[0] & 0xF)
            return 3

        if buf[2] == 0xCA and (buf[0] & 0xF) == 0x0:
            insn.itype = NewInstructions.NN_float
            insn.size = 3
            insn.Op1.type = o_reg
            insn.Op1.reg = NewInstructions.FloatRegisterBase + (buf[1] >> 4)
            insn.Op2.type = o_reg
            insn.Op2.reg = buf[1] & 0xF
            insn.Op3.type = o_imm
            insn.Op3.value = buf[0] >> 4
            return 3

        if buf[2] == 0xFA and buf[0] == 0x50:
            insn.itype = NewInstructions.NN_wfr
            insn.size = 3
            insn.Op1.type = o_reg
            insn.Op1.reg = NewInstructions.FloatRegisterBase + (buf[1] >> 4)
            insn.Op2.type = o_reg
            insn.Op2.reg = buf[1] & 0xF
            return 3

        if buf[2] == 0x4B and (buf[0] & 0xF) == 0x0:
            insn.itype = NewInstructions.NN_olt
            insn.size = 3
            insn.Op1.type = o_reg
            insn.Op1.reg = (buf[1] >> 4) # Boolean register...
            insn.Op2.type = o_reg
            insn.Op2.reg = NewInstructions.FloatRegisterBase + (buf[1] & 0xF)
            insn.Op3.type = o_reg
            insn.Op3.reg = NewInstructions.FloatRegisterBase + (buf[0] >> 4)
            return 3

        if (buf[1]>>4) == 0x0 and buf[0] == 0x76:
            insn.itype = NewInstructions.NN_bf
            insn.size = 3
            insn.Op1.type = o_reg #
            insn.Op1.reg = (buf[1] & 0xF) # Boolean register...
            insn.Op2.type = o_near
            insn.Op2.addr = insn.ea + self.sign_extend(buf[2],8) + 4
            return 3

        if (buf[1]>>4) == 0x1 and buf[0] == 0x76:
            insn.itype = NewInstructions.NN_bt
            insn.size = 3
            insn.Op1.type = o_reg #
            insn.Op1.reg = (buf[1] & 0xF) # Boolean register...
            insn.Op2.type = o_near
            insn.Op2.addr = insn.ea + self.sign_extend(buf[2],8) + 4
            return 3

        if buf[2] == 0xFA and buf[0] == 0x40:
            insn.itype = NewInstructions.NN_rfr
            insn.size = 3
            insn.Op1.type = o_reg
            insn.Op1.reg = buf[1] >> 4
            insn.Op2.type = o_reg
            insn.Op2.reg = NewInstructions.FloatRegisterBase + (buf[1] & 0xF)
            return 3

        if buf[2] == 0xFA and buf[0] == 0x60:
            insn.itype = NewInstructions.NN_neg
            insn.size = 3
            insn.Op1.type = o_reg
            insn.Op1.reg = NewInstructions.FloatRegisterBase + (buf[1] >> 4)
            insn.Op2.type = o_reg
            insn.Op2.reg = NewInstructions.FloatRegisterBase + (buf[1] & 0xF)
            return 3

        if buf[2] == 0xFA and buf[0] == 0x70:
            insn.itype = NewInstructions.NN_div0
            insn.size = 3
            insn.Op1.type = o_reg
            insn.Op1.reg = NewInstructions.FloatRegisterBase + (buf[1] >> 4)
            insn.Op2.type = o_reg
            insn.Op2.reg = NewInstructions.FloatRegisterBase + (buf[1] & 0xF)
            return 3

        if buf[2] == 0xFA and buf[0] == 0xB0:
            insn.itype = NewInstructions.NN_nexp01
            insn.size = 3
            insn.Op1.type = o_reg
            insn.Op1.reg = NewInstructions.FloatRegisterBase + (buf[1] >> 4)
            insn.Op2.type = o_reg
            insn.Op2.reg = NewInstructions.FloatRegisterBase + (buf[1] & 0xF)
            return 3

        if buf[2] == 0xFA and buf[0] == 0x30:
            insn.itype = NewInstructions.NN_const
            insn.size = 3
            insn.Op1.type = o_reg
            insn.Op1.reg = NewInstructions.FloatRegisterBase + (buf[1] >> 4)
            insn.Op2.type = o_imm
            insn.Op2.reg = (buf[1] & 0xF)
            return 3

        if (buf[1]>>4) == 0x4 and (buf[0]&0xF) == 0x3:
            insn.itype = NewInstructions.NN_ssi
            insn.size = 3
            insn.Op1.type = o_reg
            insn.Op1.reg = NewInstructions.FloatRegisterBase + (buf[0] >> 4)
            insn.Op2.type = o_reg
            insn.Op2.reg = buf[1] & 0xF
            insn.Op3.type = o_imm
            insn.Op3.value = buf[2] << 2
            return 3

        if buf[2] == 0x2A and (buf[0] & 0xF) == 0:
            insn.itype = NewInstructions.NN_mul_s
            insn.size = 3
            insn.Op1.type = o_reg
            insn.Op1.reg = NewInstructions.FloatRegisterBase + (buf[1] >> 4)
            insn.Op2.type = o_reg
            insn.Op2.reg = NewInstructions.FloatRegisterBase + (buf[1] & 0xF)
            insn.Op3.type = o_reg
            insn.Op3.reg = NewInstructions.FloatRegisterBase + (buf[0] >> 4)
            return 3

        if buf[2] == 0x4A and (buf[0] & 0xF) == 0:
            insn.itype = NewInstructions.NN_mul_s
            insn.size = 3
            insn.Op1.type = o_reg
            insn.Op1.reg = NewInstructions.FloatRegisterBase + (buf[1] >> 4)
            insn.Op2.type = o_reg
            insn.Op2.reg = NewInstructions.FloatRegisterBase + (buf[1] & 0xF)
            insn.Op3.type = o_reg
            insn.Op3.reg = NewInstructions.FloatRegisterBase + (buf[0] >> 4)
            return 3

        if buf[2] == 0xEA and (buf[0] & 0xF) == 0:
            insn.itype = NewInstructions.NN_utrunc
            insn.size = 3
            insn.Op1.type = o_reg
            insn.Op1.reg = (buf[1] >> 4)
            insn.Op2.type = o_reg
            insn.Op2.reg = NewInstructions.FloatRegisterBase + (buf[1] & 0xF)
            insn.Op3.type = o_imm
            insn.Op3.value = (buf[0] >> 4)
            return 3

        if (buf[1]>>4) == 0x0 and (buf[0] & 0xF) == 0x3:
            insn.itype = NewInstructions.NN_lsi
            insn.size = 3
            insn.Op1.type = o_reg
            insn.Op1.reg = NewInstructions.FloatRegisterBase + (buf[1] >> 4)
            insn.Op2.type = o_reg
            insn.Op2.reg = (buf[1] & 0xF)
            insn.Op3.type = o_imm
            insn.Op3.value = buf[2] << 2
            return 3

        if (buf[1]>>4) == 0x9 and (buf[0] & 0xF) == 0x3:
            insn.itype = NewInstructions.NN_ldip
            insn.size = 3
            insn.Op1.type = o_reg
            insn.Op1.reg = NewInstructions.FloatRegisterBase + (buf[0] >> 4)
            insn.Op2.type = o_reg
            insn.Op2.reg = (buf[1] & 0xF)
            insn.Op3.type = o_imm
            insn.Op3.value = buf[2] << 3
            return 3

        if (buf[1]>>4) == 0xB and (buf[0] & 0xF) == 0x3:
            insn.itype = NewInstructions.NN_ldip
            insn.size = 3
            insn.Op1.type = o_reg
            insn.Op1.reg = NewInstructions.FloatRegisterBase + (buf[0] >> 4)
            insn.Op2.type = o_reg
            insn.Op2.reg = (buf[1] & 0xF)
            insn.Op3.type = o_imm
            insn.Op3.value = buf[2] << 3
            return 3

        if (buf[1]>>4) == 0x7 and (buf[0] & 0xF) == 0x3:
            insn.itype = NewInstructions.NN_sdi
            insn.size = 3
            insn.Op1.type = o_reg
            insn.Op1.reg = NewInstructions.FloatRegisterBase + (buf[0] >> 4)
            insn.Op2.type = o_reg
            insn.Op2.reg = (buf[1] & 0xF)
            insn.Op3.type = o_imm
            insn.Op3.value = buf[2] << 3
            return 3

        if buf[2] == 0x0A and (buf[0] & 0xF) == 0x0:
            insn.itype = NewInstructions.NN_add
            insn.size = 3
            insn.Op1.type = o_reg
            insn.Op1.reg = NewInstructions.FloatRegisterBase + (buf[1] >> 4)
            insn.Op2.type = o_reg
            insn.Op2.reg = NewInstructions.FloatRegisterBase + (buf[1] & 0xF)
            insn.Op3.type = o_reg
            insn.Op3.reg = NewInstructions.FloatRegisterBase + (buf[0] >> 4)
            return 3

        if buf[2] == 0x6A and (buf[0] & 0xF) == 0x0:
            insn.itype = NewInstructions.NN_maddn
            insn.size = 3
            insn.Op1.type = o_reg
            insn.Op1.reg = NewInstructions.FloatRegisterBase + (buf[1] >> 4)
            insn.Op2.type = o_reg
            insn.Op2.reg = NewInstructions.FloatRegisterBase + (buf[1] & 0xF)
            insn.Op3.type = o_reg
            insn.Op3.reg = NewInstructions.FloatRegisterBase + (buf[0] >> 4)
            return 3

        if buf[2] == 0x7A and (buf[0] & 0xF) == 0x0:
            insn.itype = NewInstructions.NN_divn
            insn.size = 3
            insn.Op1.type = o_reg
            insn.Op1.reg = NewInstructions.FloatRegisterBase + (buf[1] >> 4)
            insn.Op2.type = o_reg
            insn.Op2.reg = NewInstructions.FloatRegisterBase + (buf[1] & 0xF)
            insn.Op3.type = o_reg
            insn.Op3.reg = NewInstructions.FloatRegisterBase + (buf[0] >> 4)
            return 3

        if buf[2] == 0x7B and (buf[0] & 0xF) == 0x0:
            insn.itype = NewInstructions.NN_ule
            insn.size = 3
            insn.Op1.type = o_reg
            insn.Op1.reg = (buf[1] >> 4)
            insn.Op2.type = o_reg
            insn.Op2.reg = NewInstructions.FloatRegisterBase + (buf[1] & 0xF)
            insn.Op3.type = o_reg
            insn.Op3.reg = NewInstructions.FloatRegisterBase + (buf[0] >> 4)
            return 3

        if buf[2] == 0xFA and buf[0] == 0xD0:
            insn.itype = NewInstructions.NN_mkdadj
            insn.size = 3
            insn.Op1.type = o_reg
            insn.Op1.reg = NewInstructions.FloatRegisterBase + (buf[1] >> 4)
            insn.Op2.type = o_reg
            insn.Op2.reg = NewInstructions.FloatRegisterBase + (buf[1] & 0xF)
            return 3

        if buf[2] == 0xFA and buf[0] == 0xE0:
            insn.itype = NewInstructions.NN_addexp
            insn.size = 3
            insn.Op1.type = o_reg
            insn.Op1.reg = NewInstructions.FloatRegisterBase + (buf[1] >> 4)
            insn.Op2.type = o_reg
            insn.Op2.reg = NewInstructions.FloatRegisterBase + (buf[1] & 0xF)
            return 3

        if buf[2] == 0xFA and buf[0] == 0xF0:
            insn.itype = NewInstructions.NN_addexpm
            insn.size = 3
            insn.Op1.type = o_reg
            insn.Op1.reg = NewInstructions.FloatRegisterBase + (buf[1] >> 4)
            insn.Op2.type = o_reg
            insn.Op2.reg = NewInstructions.FloatRegisterBase + (buf[1] & 0xF)
            return 3

        if buf[2] == 0xFA and buf[0] == 0x10:
            insn.itype = NewInstructions.NN_abs
            insn.size = 3
            insn.Op1.type = o_reg
            insn.Op1.reg = NewInstructions.FloatRegisterBase + (buf[1] >> 4)
            insn.Op2.type = o_reg
            insn.Op2.reg = NewInstructions.FloatRegisterBase + (buf[1] & 0xF)
            return 3

        if buf[2] == 0x9A and (buf[0] & 0xF) == 0x0:
            insn.itype = NewInstructions.NN_trunc
            insn.size = 3
            insn.Op1.type = o_reg
            insn.Op1.reg = (buf[1] >> 4)
            insn.Op2.type = o_reg
            insn.Op2.reg = NewInstructions.FloatRegisterBase + (buf[1] & 0xF)
            insn.Op3.type = o_imm
            insn.Op3.reg = 2 ** (buf[0] >> 4)
            return 3

        if buf[2] == 0xDA and (buf[0] & 0xF) == 0x0:
            insn.itype = NewInstructions.NN_ufloat
            insn.size = 3
            insn.Op1.type = o_reg
            insn.Op1.reg = NewInstructions.FloatRegisterBase + (buf[1] >> 4)
            insn.Op2.type = o_reg
            insn.Op2.reg = (buf[1] & 0xF)
            insn.Op3.type = o_imm
            insn.Op3.reg = 2 ** (buf[0] >> 4)
            return 3

        if buf[2] == 0x6B and (buf[0] & 0xF) == 0x0:
            insn.itype = NewInstructions.NN_ufloat
            insn.size = 3
            insn.Op1.type = o_reg
            insn.Op1.reg = (buf[1] >> 4)
            insn.Op2.type = o_reg
            insn.Op2.reg = NewInstructions.FloatRegisterBase + (buf[1] & 0xF)
            insn.Op3.type = o_reg
            insn.Op3.reg = NewInstructions.FloatRegisterBase + (buf[0] >> 4)
            return 3

        if buf[2] == 0xFA and buf[0] == 0x0:
            insn.itype = NewInstructions.NN_mov
            insn.size = 3
            insn.Op1.type = o_reg
            insn.Op1.reg = NewInstructions.FloatRegisterBase + (buf[1] >> 4)
            insn.Op2.type = o_reg
            insn.Op2.reg = NewInstructions.FloatRegisterBase + (buf[1] & 0xF)
            return 3

        if buf[2] == 0x1A and (buf[0] & 0xF) == 0x0:
            insn.itype = NewInstructions.NN_sub
            insn.size = 3
            insn.Op1.type = o_reg
            insn.Op1.reg = NewInstructions.FloatRegisterBase + (buf[1] >> 4)
            insn.Op2.type = o_reg
            insn.Op2.reg = NewInstructions.FloatRegisterBase + (buf[1] & 0xF)
            insn.Op3.type = o_reg
            insn.Op3.reg = NewInstructions.FloatRegisterBase + (buf[0] >> 4)
            return 3

        if buf[2] == 0x5A and (buf[0] & 0xF) == 0x0:
            insn.itype = NewInstructions.NN_msub
            insn.size = 3
            insn.Op1.type = o_reg
            insn.Op1.reg = NewInstructions.FloatRegisterBase + (buf[1] >> 4)
            insn.Op2.type = o_reg
            insn.Op2.reg = NewInstructions.FloatRegisterBase + (buf[1] & 0xF)
            insn.Op3.type = o_reg
            insn.Op3.reg = NewInstructions.FloatRegisterBase + (buf[0] >> 4)
            return 3

        return False

    def ev_ana_insn(self, insn):
        return self.decode_instruction(insn)

    def ev_out_insn(self, outctx):
        insn = outctx.insn
        if insn.itype == NewInstructions.NN_nop:
            # There's some dumb code that assumes size==2 opcodes are defined in the base code
            self.ev_out_mnem(outctx)
            outctx.flush_outbuf()
            return True
        return False

    def ev_out_mnem(self, outctx):
        insn = outctx.insn
        global NEWINSN_COLOR

        if (insn.itype >= CUSTOM_INSN_ITYPE) and (insn.itype in NewInstructions.lst):
            mnem = NewInstructions.lst[insn.itype]
            outctx.out_tagon(NEWINSN_COLOR)
            outctx.out_line(mnem)
            if insn.itype in [NewInstructions.NN_rur, NewInstructions.NN_wur]:
                outctx.out_symbol(".")
                outctx.out_line(NewInstructions.UserRegister[insn.insnpref])
            if insn.itype in [NewInstructions.NN_rsr, NewInstructions.NN_wsr, NewInstructions.NN_xsr]:
                outctx.out_symbol(".")
                if insn.insnpref in NewInstructions.SpecialRegister:
                    outctx.out_line(NewInstructions.SpecialRegister[insn.insnpref])
                else:
                    outctx.out_line("unk:"+str(insn.insnpref))
            outctx.out_tagoff(NEWINSN_COLOR)

            # TODO: how can MNEM_width be determined programmatically?
            MNEM_WIDTH = 8
            width = max(1, MNEM_WIDTH - len(mnem))
            outctx.out_line(' ' * width)

            return True
        return False

    def ev_out_operand(self, outctx, op):
        insn = outctx.insn
        if insn.itype in NewInstructions.lst:
            if op.type == o_displ:
                outctx.out_value(op, OOF_ADDR)
                outctx.out_register(ph_get_regnames()[op.reg])
                return True
            elif op.type == o_void:
                return True
        return False
#--------------------------------------------------------------------------
class XtensaESP(plugin_t):
    flags = PLUGIN_PROC | PLUGIN_HIDE
    comment = ""
    wanted_hotkey = ""
    help = "Adds support for additional Xtensa instructions"
    wanted_name = "XtensaESP"

    def __init__(self):
        self.prochook = None

    def init(self):
        if ph_get_id() != PLFM_XTENSA:
            return PLUGIN_SKIP

        self.prochook = xtensa_idp_hook_t()
        self.prochook.hook()
        print ("%s initialized." % XtensaESP.wanted_name)
        return PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        if self.prochook:
            self.prochook.unhook()
#--------------------------------------------------------------------------
def PLUGIN_ENTRY():
    return XtensaESP()

