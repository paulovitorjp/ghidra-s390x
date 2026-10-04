PROG     CSECT
         USING  *,15
BT1      NOPR  0
* EBCDIC immediates
E0001    MVI    0(4),C'A'
E0002    MVI    0(4),C' '
E0003    CLI    0(4),C'Z'
E0004    CLI    0(4),C'0'
E0005    NI     0(4),C'A'
E0006    OI     0(4),C' '
E0007    XI     0(4),C'Z'
* --- Zoned decimal source (EBCDIC digits F0-F9)
E0008    PACK   0(3,4),ZD1
E0009    UNPK   0(6,4),PD1
E0010    ZAP    0(3,4),ZD1
E0011    CP     0(3,4),ZD1
E0012    AP     0(3,4),ZD1
* --- Translate / translate-and-test with EBCDIC table
E0013    TR     0(16,4),TRTAB
E0014    TRT    0(16,4),TRTAB
* --- Edit with pattern (EBCDIC 0x40 blank fill)
E0015    ED     0(8,4),EDPAT
E0016    EDMK   0(8,4),EDPAT
* --- Move with EBCDIC source data
E0017    MVC    0(8,4),EBCDAT
E0018    CLC    0(8,4),EBCDAT
BT2      NOPR  0
* --- Data areas (EBCDIC)
ZD1      DC     C'12345'
PD1      DC     P'123'
TRTAB    DC     256C' '
EDPAT    DC     X'40206B202020'
EBCDAT   DC     C'HELLO123'
         END
