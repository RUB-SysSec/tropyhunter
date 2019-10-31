#from amoco.arch.x64 import cpu_x64
import unicorn

class RegistersX64(object):

    rax = 0
    rcx = 1
    rdx = 2
    rbx = 3
    rsp = 4
    rbp = 5
    rsi = 6
    rdi = 7
    r8 = 8
    r9 = 9
    r10 = 10
    r11 = 11
    r12 = 12
    r13 = 13
    r14 = 14
    r15 = 15
    al = 16
    cl = 17
    dl = 18
    bl = 19
    ah = 20
    ch = 21
    dh = 22
    bh = 23
    spl = 24
    bpl = 25
    sil = 26
    dil = 27
    mm0 = 56
    mm1 = 57
    mm2 = 58
    mm3 = 59
    mm4 = 60
    mm5 = 61
    mm6 = 62
    mm7 = 63
    xmm0 = 64
    xmm1 = 65
    xmm2 = 66
    xmm3 = 67
    xmm4 = 68
    xmm5 = 69
    xmm6 = 70
    xmm7 = 71
    xmm8 = 72
    xmm9 = 73
    xmm10 = 74
    xmm11 = 75
    xmm12 = 76
    xmm13 = 77
    xmm14 = 78
    xmm15 = 79
    ymm0 = 81
    ymm1 = 82
    ymm2 = 83
    ymm3 = 84
    ymm4 = 85
    ymm5 = 86
    ymm6 = 87
    ymm7 = 88
    ymm8 = 89
    ymm9 = 90
    ymm10 = 91
    ymm11 = 92
    ymm12 = 93
    ymm13 = 94
    ymm14 = 95
    ymm15 = 96
    retval = -1

    _to_str = {
        rax: "rax",
        rcx: "rcx",
        rdx: "rdx",
        rbx: "rbx",
        rsp: "rsp",
        rbp: "rbp",
        rsi: "rsi",
        rdi: "rdi",
        r8: "r8",
        r9: "r9",
        r10: "r10",
        r11: "r11",
        r12: "r12",
        r13: "r13",
        r14: "r14",
        r15: "r15",
        al: "al",
        cl: "cl",
        dl: "dl",
        bl: "bl",
        ah: "ah",
        ch: "ch",
        dh: "dh",
        bh: "bh",
        spl: "spl",
        bpl: "bpl",
        sil: "sil",
        dil: "dil",
        mm0: "mm0",
        mm1: "mm1",
        mm2: "mm2",
        mm3: "mm3",
        mm4: "mm4",
        mm5: "mm5",
        mm6: "mm6",
        mm7: "mm7",
        xmm0: "xmm0",
        xmm1: "xmm1",
        xmm2: "xmm2",
        xmm3: "xmm3",
        xmm4: "xmm4",
        xmm5: "xmm5",
        xmm6: "xmm6",
        xmm7: "xmm7",
        xmm8: "xmm8",
        xmm9: "xmm9",
        xmm10: "xmm10",
        xmm11: "xmm11",
        xmm12: "xmm12",
        xmm13: "xmm13",
        xmm14: "xmm14",
        xmm15: "xmm15",
        ymm0: "ymm0",
        ymm1: "ymm1",
        ymm2: "ymm2",
        ymm3: "ymm3",
        ymm4: "ymm4",
        ymm5: "ymm5",
        ymm6: "ymm6",
        ymm7: "ymm7",
        ymm8: "ymm8",
        ymm9: "ymm9",
        ymm10: "ymm10",
        ymm11: "ymm11",
        ymm12: "ymm12",
        ymm13: "ymm13",
        ymm14: "ymm14",
        ymm15: "ymm15",
        retval: "retval",
    }

    _to_idx = {
        "eax": rax,
        "ecx": rcx,
        "edx": rdx,
        "ebx": rbx,
        "esp": rsp,
        "ebp": rbp,
        "esi": rsi,
        "edi": rdi,
        "rax": rax,
        "rcx": rcx,
        "rdx": rdx,
        "rbx": rbx,
        "rsp": rsp,
        "rbp": rbp,
        "rsi": rsi,
        "rdi": rdi,
        "r8d": r8,
        "r9d": r9,
        "r10d": r10,
        "r11d": r11,
        "r12d": r12,
        "r13d": r13,
        "r14d": r14,
        "r15d": r15,
        "r8": r8,
        "r9": r9,
        "r10": r10,
        "r11": r11,
        "r12": r12,
        "r13": r13,
        "r14": r14,
        "r15": r15,
        "al": al,
        "cl": cl,
        "dl": dl,
        "bl": bl,
        "ah": ah,
        "ch": ch,
        "dh": dh,
        "bh": bh,
        "spl": spl,
        "bpl": bpl,
        "sil": sil,
        "dil": dil,
        "xmm0": xmm0,
        "xmm1": xmm1,
        "xmm2": xmm2,
        "xmm3": xmm3,
        "xmm4": xmm4,
        "xmm5": xmm5,
        "xmm6": xmm6,
        "xmm7": xmm7,
        "xmm8": xmm8,
        "xmm9": xmm9,
        "xmm10": xmm10,
        "xmm11": xmm11,
        "xmm12": xmm12,
        "xmm13": xmm13,
        "xmm14": xmm14,
        "xmm15": xmm15,
        "ymm0": ymm0,
        "ymm1": ymm1,
        "ymm2": ymm2,
        "ymm3": ymm3,
        "ymm4": ymm4,
        "ymm5": ymm5,
        "ymm6": ymm6,
        "ymm7": ymm7,
        "ymm8": ymm8,
        "ymm9": ymm9,
        "ymm10": ymm10,
        "ymm11": ymm11,
        "ymm12": ymm12,
        "ymm13": ymm13,
        "ymm14": ymm14,
        "ymm15": ymm15,
        "retval": retval,
    }

    '''
    _to_amoco = {
        rax: cpu_x64.rax,
        rcx: cpu_x64.rcx,
        rdx: cpu_x64.rdx,
        rbx: cpu_x64.rbx,
        rsp: cpu_x64.rsp,
        rbp: cpu_x64.rbp,
        rsi: cpu_x64.rsi,
        rdi: cpu_x64.rdi,
        r8: cpu_x64.r8,
        r9: cpu_x64.r9,
        r10: cpu_x64.r10,
        r11: cpu_x64.r11,
        r12: cpu_x64.r12,
        r13: cpu_x64.r13,
        r14: cpu_x64.r14,
        r15: cpu_x64.r15,
        al: cpu_x64.al,
        cl: cpu_x64.cl,
        dl: cpu_x64.dl,
        bl: cpu_x64.bl,
        ah: cpu_x64.ah,
        ch: cpu_x64.ch,
        dh: cpu_x64.dh,
        bh: cpu_x64.bh,
        spl: cpu_x64.spl,
        bpl: cpu_x64.bpl,
        sil: cpu_x64.sil,
        dil: cpu_x64.dil,
        mm0: cpu_x64.mmregs[0],
        mm1: cpu_x64.mmregs[1],
        mm2: cpu_x64.mmregs[2],
        mm3: cpu_x64.mmregs[3],
        mm4: cpu_x64.mmregs[4],
        mm5: cpu_x64.mmregs[5],
        mm6: cpu_x64.mmregs[6],
        mm7: cpu_x64.mmregs[7],
        xmm0: cpu_x64.xmmregs[0],
        xmm1: cpu_x64.xmmregs[1],
        xmm2: cpu_x64.xmmregs[2],
        xmm3: cpu_x64.xmmregs[3],
        xmm4: cpu_x64.xmmregs[4],
        xmm5: cpu_x64.xmmregs[5],
        xmm6: cpu_x64.xmmregs[6],
        xmm7: cpu_x64.xmmregs[7],
        xmm8: cpu_x64.xmmregs[8],
        xmm9: cpu_x64.xmmregs[9],
        xmm10: cpu_x64.xmmregs[10],
        xmm11: cpu_x64.xmmregs[11],
        xmm12: cpu_x64.xmmregs[12],
        xmm13: cpu_x64.xmmregs[13],
        xmm14: cpu_x64.xmmregs[14],
        xmm15: cpu_x64.xmmregs[15],
        ymm0: cpu_x64.ymmregs[0],
        ymm1: cpu_x64.ymmregs[1],
        ymm2: cpu_x64.ymmregs[2],
        ymm3: cpu_x64.ymmregs[3],
        ymm4: cpu_x64.ymmregs[4],
        ymm5: cpu_x64.ymmregs[5],
        ymm6: cpu_x64.ymmregs[6],
        ymm7: cpu_x64.ymmregs[7],
        ymm8: cpu_x64.ymmregs[8],
        ymm9: cpu_x64.ymmregs[9],
        ymm10: cpu_x64.ymmregs[10],
        ymm11: cpu_x64.ymmregs[11],
        ymm12: cpu_x64.ymmregs[12],
        ymm13: cpu_x64.ymmregs[13],
        ymm14: cpu_x64.ymmregs[14],
        ymm15: cpu_x64.ymmregs[15],
    }
    '''

    _to_unicorn = {
        rax: unicorn.x86_const.UC_X86_REG_RAX,
        rcx: unicorn.x86_const.UC_X86_REG_RCX,
        rdx: unicorn.x86_const.UC_X86_REG_RDX,
        rbx: unicorn.x86_const.UC_X86_REG_RBX,
        rsp: unicorn.x86_const.UC_X86_REG_RSP,
        rbp: unicorn.x86_const.UC_X86_REG_RBP,
        rsi: unicorn.x86_const.UC_X86_REG_RSI,
        rdi: unicorn.x86_const.UC_X86_REG_RDI,
        r8: unicorn.x86_const.UC_X86_REG_R8,
        r9: unicorn.x86_const.UC_X86_REG_R9,
        r10: unicorn.x86_const.UC_X86_REG_R10,
        r11: unicorn.x86_const.UC_X86_REG_R11,
        r12: unicorn.x86_const.UC_X86_REG_R12,
        r13: unicorn.x86_const.UC_X86_REG_R13,
        r14: unicorn.x86_const.UC_X86_REG_R14,
        r15: unicorn.x86_const.UC_X86_REG_R15,
        xmm0: unicorn.x86_const.UC_X86_REG_XMM0,
    }

    _from_unicorn = {
        unicorn.x86_const.UC_X86_REG_RAX: rax,
        unicorn.x86_const.UC_X86_REG_RCX: rcx,
        unicorn.x86_const.UC_X86_REG_RDX: rdx,
        unicorn.x86_const.UC_X86_REG_RBX: rbx,
        unicorn.x86_const.UC_X86_REG_RSP: rsp,
        unicorn.x86_const.UC_X86_REG_RBP: rbp,
        unicorn.x86_const.UC_X86_REG_RSI: rsi,
        unicorn.x86_const.UC_X86_REG_RDI: rdi,
        unicorn.x86_const.UC_X86_REG_R8: r8,
        unicorn.x86_const.UC_X86_REG_R9: r9,
        unicorn.x86_const.UC_X86_REG_R10: r10,
        unicorn.x86_const.UC_X86_REG_R11: r11,
        unicorn.x86_const.UC_X86_REG_R12: r12,
        unicorn.x86_const.UC_X86_REG_R13: r13,
        unicorn.x86_const.UC_X86_REG_R14: r14,
        unicorn.x86_const.UC_X86_REG_R15: r15,
        unicorn.x86_const.UC_X86_REG_XMM0: xmm0,
    }

    @staticmethod
    def to_str(reg: int):
        if reg not in RegistersX64._to_str:
            raise NotImplementedError('Unknown register index %d.' %
                                       reg)
        return RegistersX64._to_str[reg]

    @staticmethod
    def to_idx(reg_str: str):
        if reg_str not in RegistersX64._to_idx:
            raise NotImplementedError('Unknown register string %s.' %
                                       reg_str)
        return RegistersX64._to_idx[reg_str]

    '''
    @staticmethod
    def to_amoco(reg: int):
        if reg not in RegistersX64._to_amoco:
            raise NotImplementedError('Unknown amoco register index %d.' %
                                       reg)
        return RegistersX64._to_amoco[reg]
    '''

    @staticmethod
    def to_unicorn(reg: int):
        if reg not in RegistersX64._to_unicorn:
            raise NotImplementedError('Unknown unicorn register index %d.' %
                                       reg)
        return RegistersX64._to_unicorn[reg]

    @staticmethod
    def from_str_to_unicorn(reg_str: str):
        return RegistersX64.to_unicorn(RegistersX64.to_idx(reg_str))

    @staticmethod
    def from_unicorn(reg: int):
        if reg not in RegistersX64._from_unicorn:
            raise NotImplementedError('Unknown unicorn register index %d.' %
                                       reg)
        return RegistersX64._from_unicorn[reg]

    @staticmethod
    def from_unicorn_to_str(reg: int):
        idx = RegistersX64.from_unicorn(reg)
        return RegistersX64.to_str(idx)


class CallingConvention(object):
    def check(self, reg_idx: int):
        raise NotImplementedError("Not implemented.")


class CallingConventionX64(CallingConvention):

    system_v = [
            RegistersX64.rdi,
            RegistersX64.rsi,
            RegistersX64.rdx,
            RegistersX64.rcx,
            RegistersX64.r8,
            RegistersX64.r9]

    def __init__(self):
        pass

    def check(self, reg_idx: int):
        return reg_idx in self.system_v

    def get_registers(self):
        return list(self.system_v)