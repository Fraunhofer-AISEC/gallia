"""
gallia-analyze Failure module
"""
from enum import IntEnum


class Failure(IntEnum):
    """
    enum class for failures
    """

    UNKNOWN = 0xFF
    UNDEFINED = 0xF0

    OK_SERV = 0x00
    OK_SERV_A = 0x01
    OK_SERV_B = 0x02
    OK_SERV_C = 0x03
    OK_SERV_D = 0x04
    OK_SERV_E = 0x05
    OK_SERV_F = 0x06
    OK_SERV_G = 0x07
    OK_SERV_H = 0x08
    OK_SERV_I = 0x09
    OK_SERV_J = 0x0A
    OK_SERV_K = 0x0B
    OK_SERV_L = 0x0C
    OK_SERV_M = 0x0D
    OK_SERV_N = 0x0E
    OK_SERV_O = 0x0F

    OK_IDEN = 0x10
    OK_IDEN_A = 0x11
    OK_IDEN_B = 0x12
    OK_IDEN_C = 0x13
    OK_IDEN_D = 0x14
    OK_IDEN_E = 0x15
    OK_IDEN_F = 0x16
    OK_IDEN_G = 0x17
    OK_IDEN_H = 0x18
    OK_IDEN_I = 0x19
    OK_IDEN_J = 0x1A
    OK_IDEN_K = 0x1B
    OK_IDEN_L = 0x1C
    OK_IDEN_M = 0x1D
    OK_IDEN_N = 0x1E
    OK_IDEN_O = 0x1F

    UNDOC_SERV = 0x20
    UNDOC_SERV_A = 0x21
    UNDOC_SERV_B = 0x22
    UNDOC_SERV_C = 0x23
    UNDOC_SERV_D = 0x24
    UNDOC_SERV_E = 0x25
    UNDOC_SERV_F = 0x26
    UNDOC_SERV_G = 0x27
    UNDOC_SERV_H = 0x28
    UNDOC_SERV_I = 0x29
    UNDOC_SERV_J = 0x2A
    UNDOC_SERV_K = 0x2B
    UNDOC_SERV_L = 0x2C
    UNDOC_SERV_M = 0x2D
    UNDOC_SERV_N = 0x2E
    UNDOC_SERV_O = 0x2F

    UNDOC_IDEN = 0x30
    UNDOC_IDEN_A = 0x31
    UNDOC_IDEN_B = 0x32
    UNDOC_IDEN_C = 0x33
    UNDOC_IDEN_D = 0x34
    UNDOC_IDEN_E = 0x35
    UNDOC_IDEN_F = 0x36
    UNDOC_IDEN_G = 0x37
    UNDOC_IDEN_H = 0x38
    UNDOC_IDEN_I = 0x39
    UNDOC_IDEN_J = 0x3A
    UNDOC_IDEN_K = 0x3B
    UNDOC_IDEN_L = 0x3C
    UNDOC_IDEN_M = 0x3D
    UNDOC_IDEN_N = 0x3E
    UNDOC_IDEN_O = 0x3F

    MISS_SERV = 0x40
    MISS_SERV_A = 0x41
    MISS_SERV_B = 0x42
    MISS_SERV_C = 0x43
    MISS_SERV_D = 0x44
    MISS_SERV_E = 0x45
    MISS_SERV_F = 0x46
    MISS_SERV_G = 0x47
    MISS_SERV_H = 0x48
    MISS_SERV_I = 0x49
    MISS_SERV_J = 0x4A
    MISS_SERV_K = 0x4B
    MISS_SERV_L = 0x4C
    MISS_SERV_M = 0x4D
    MISS_SERV_N = 0x4E
    MISS_SERV_O = 0x4F

    MISS_IDEN = 0x50
    MISS_IDEN_A = 0x51
    MISS_IDEN_B = 0x52
    MISS_IDEN_C = 0x53
    MISS_IDEN_D = 0x54
    MISS_IDEN_E = 0x55
    MISS_IDEN_F = 0x56
    MISS_IDEN_G = 0x57
    MISS_IDEN_H = 0x58
    MISS_IDEN_I = 0x59
    MISS_IDEN_J = 0x5A
    MISS_IDEN_K = 0x5B
    MISS_IDEN_L = 0x5C
    MISS_IDEN_M = 0x5D
    MISS_IDEN_N = 0x5E
    MISS_IDEN_O = 0x5F

    DFT_RES = 0x70
    DFT_RES_A = 0x71
    DFT_RES_B = 0x72
    DFT_RES_C = 0x73
    DFT_RES_D = 0x74
    DFT_RES_E = 0x75
    DFT_RES_F = 0x76
    DFT_RES_G = 0x77
    DFT_RES_H = 0x78
    DFT_RES_I = 0x79
    DFT_RES_J = 0x7A
    DFT_RES_K = 0x7B
    DFT_RES_L = 0x7C
    DFT_RES_M = 0x7D
    DFT_RES_N = 0x7E
    DFT_RES_O = 0x7F
