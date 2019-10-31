

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
    es = 29
    cs = 30
    ss = 31
    ds = 32
    fs = 33
    gs = 34
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
    bnd0 = 97
    bnd1 = 98
    bnd2 = 99
    bnd3 = 100
    xmm16 = 101
    xmm17 = 102
    xmm18 = 103
    xmm19 = 104
    xmm20 = 105
    xmm21 = 106
    xmm22 = 107
    xmm23 = 108
    xmm24 = 109
    xmm25 = 110
    xmm26 = 111
    xmm27 = 112
    xmm28 = 113
    xmm29 = 114
    xmm30 = 115
    xmm31 = 116
    ymm16 = 117
    ymm17 = 118
    ymm18 = 119
    ymm19 = 120
    ymm20 = 121
    ymm21 = 122
    ymm22 = 123
    ymm23 = 124
    ymm24 = 125
    ymm25 = 126
    ymm26 = 127
    ymm27 = 128
    ymm28 = 129
    ymm29 = 130
    ymm30 = 131
    ymm31 = 132
    zmm0 = 133
    zmm1 = 134
    zmm2 = 135
    zmm3 = 136
    zmm4 = 137
    zmm5 = 138
    zmm6 = 139
    zmm7 = 140
    zmm8 = 141
    zmm9 = 142
    zmm10 = 143
    zmm11 = 144
    zmm12 = 145
    zmm13 = 146
    zmm14 = 147
    zmm15 = 148
    zmm16 = 149
    zmm17 = 150
    zmm18 = 151
    zmm19 = 152
    zmm20 = 153
    zmm21 = 154
    zmm22 = 155
    zmm23 = 156
    zmm24 = 157
    zmm25 = 158
    zmm26 = 159
    zmm27 = 160
    zmm28 = 161
    zmm29 = 162
    zmm30 = 163
    zmm31 = 164
    k1 = 166
    k2 = 167
    k3 = 168
    k4 = 169
    k5 = 170
    k6 = 171
    k7 = 172

    # Special internal return value register.
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
        es: "es",
        cs: "cs",
        ss: "ss",
        ds: "ds",
        fs: "fs",
        gs: "gs",
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
        bnd0: "bnd0",
        bnd1: "bnd1",
        bnd2: "bnd2",
        bnd3: "bnd3",
        xmm16: "xmm16",
        xmm17: "xmm17",
        xmm18: "xmm18",
        xmm19: "xmm19",
        xmm20: "xmm20",
        xmm21: "xmm21",
        xmm22: "xmm22",
        xmm23: "xmm23",
        xmm24: "xmm24",
        xmm25: "xmm25",
        xmm26: "xmm26",
        xmm27: "xmm27",
        xmm28: "xmm28",
        xmm29: "xmm29",
        xmm30: "xmm30",
        xmm31: "xmm31",
        ymm16: "ymm16",
        ymm17: "ymm17",
        ymm18: "ymm18",
        ymm19: "ymm19",
        ymm20: "ymm20",
        ymm21: "ymm21",
        ymm22: "ymm22",
        ymm23: "ymm23",
        ymm24: "ymm24",
        ymm25: "ymm25",
        ymm26: "ymm26",
        ymm27: "ymm27",
        ymm28: "ymm28",
        ymm29: "ymm29",
        ymm30: "ymm30",
        ymm31: "ymm31",
        zmm0: "zmm0",
        zmm1: "zmm1",
        zmm2: "zmm2",
        zmm3: "zmm3",
        zmm4: "zmm4",
        zmm5: "zmm5",
        zmm6: "zmm6",
        zmm7: "zmm7",
        zmm8: "zmm8",
        zmm9: "zmm9",
        zmm10: "zmm10",
        zmm11: "zmm11",
        zmm12: "zmm12",
        zmm13: "zmm13",
        zmm14: "zmm14",
        zmm15: "zmm15",
        zmm16: "zmm16",
        zmm17: "zmm17",
        zmm18: "zmm18",
        zmm19: "zmm19",
        zmm20: "zmm20",
        zmm21: "zmm21",
        zmm22: "zmm22",
        zmm23: "zmm23",
        zmm24: "zmm24",
        zmm25: "zmm25",
        zmm26: "zmm26",
        zmm27: "zmm27",
        zmm28: "zmm28",
        zmm29: "zmm29",
        zmm30: "zmm30",
        zmm31: "zmm31",
        k1: "k1",
        k2: "k2",
        k3: "k3",
        k4: "k4",
        k5: "k5",
        k6: "k6",
        k7: "k7",
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
        "es": es,
        "cs": cs,
        "ss": ss,
        "ds": ds,
        "fs": fs,
        "gs": gs,
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
        "ymm21": ymm21,
        "ymm22": ymm22,
        "ymm23": ymm23,
        "ymm24": ymm24,
        "ymm25": ymm25,
        "ymm26": ymm26,
        "ymm27": ymm27,
        "ymm28": ymm28,
        "ymm29": ymm29,
        "ymm30": ymm30,
        "ymm31": ymm31,
        "bnd0": bnd0,
        "bnd1": bnd1,
        "bnd2": bnd2,
        "bnd3": bnd3,
        "xmm16": xmm16,
        "xmm17": xmm17,
        "xmm18": xmm18,
        "xmm19": xmm19,
        "xmm20": xmm20,
        "xmm21": xmm21,
        "xmm22": xmm22,
        "xmm23": xmm23,
        "xmm24": xmm24,
        "xmm25": xmm25,
        "xmm26": xmm26,
        "xmm27": xmm27,
        "xmm28": xmm28,
        "xmm29": xmm29,
        "xmm30": xmm30,
        "xmm31": xmm31,
        "ymm16": ymm16,
        "ymm17": ymm17,
        "ymm18": ymm18,
        "ymm19": ymm19,
        "ymm20": ymm20,
        "zmm0": zmm0,
        "zmm1": zmm1,
        "zmm2": zmm2,
        "zmm3": zmm3,
        "zmm4": zmm4,
        "zmm5": zmm5,
        "zmm6": zmm6,
        "zmm7": zmm7,
        "zmm8": zmm8,
        "zmm9": zmm9,
        "zmm10": zmm10,
        "zmm11": zmm11,
        "zmm12": zmm12,
        "zmm13": zmm13,
        "zmm14": zmm14,
        "zmm15": zmm15,
        "zmm16": zmm16,
        "zmm17": zmm17,
        "zmm18": zmm18,
        "zmm19": zmm19,
        "zmm20": zmm20,
        "zmm21": zmm21,
        "zmm22": zmm22,
        "zmm23": zmm23,
        "zmm24": zmm24,
        "zmm25": zmm25,
        "zmm26": zmm26,
        "zmm27": zmm27,
        "zmm28": zmm28,
        "zmm29": zmm29,
        "zmm30": zmm30,
        "zmm31": zmm31,
        "k1": k1,
        "k2": k2,
        "k3": k3,
        "k4": k4,
        "k5": k5,
        "k6": k6,
        "k7": k7,
        "retval": retval,
    }

    def __init__(self):
        pass

    def to_str(self, reg):
        if reg not in RegistersX64._to_str:
            raise NotImplementedError('Unknown register index %d.' %
                                       reg)
        return RegistersX64._to_str[reg]

    def to_idx(self, reg_str):
        if reg_str not in RegistersX64._to_idx:
            raise NotImplementedError('Unknown register string %s.' %
                                       reg_str)
        return RegistersX64._to_idx[reg_str]