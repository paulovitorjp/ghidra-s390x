FIXREGS  CSECT
* --- 029E register-spec fixes, 2026-10-04. Original T-labels kept.
* --- See tests/REGFIX_REPORT.md for constraints.
T0457    SRDL   2,16(3)
T0466    SLDL   2,16(3)
T0475    SRDA   2,16(3)
T0484    SLDA   2,16(3)
T0509    TRE    0,2
T0510    TRTE   0,2
T0511    TRTT   0,2
T0513    TROT   0,2
T0515    CLCLE  2,4,16(3)
T0516    CLCLU  2,4,74565(3)
T0673    FIXBRA 0,7,0,7
T0693    LDXR   1,0
T0696    AXR    0,0
T0697    SXR    0,0
T0699    LPXR   0,0
T0700    LNXR   0,0
T0701    LTXR   0,0
T0702    LCXR   0,0
T0704    LEXR   0,0
T0705    FIXR   0,0
T0706    CXR    0,0
T4095    M      2,16(2,3)
T4113    MR     2,2
T4131    ML     2,74565(2,3)
T4140    MLR    2,2
T4149    MLG    2,74565(2,3)
T4158    MLGR   2,2
T4167    D      2,16(2,3)
T4176    DR     2,2
T4203    DLG    2,74565(2,3)
T4212    DLGR   2,2
T4221    DSG    2,74565(2,3)
T4230    DSGR   2,2
T4239    DSGF   2,74565(2,3)
T4248    DSGFR  2,2
T4265    KM     2,2
T4268    KMO    2,2
T4272    PPNO   2,2
T4274    KMCTR  2,4,2
         END
