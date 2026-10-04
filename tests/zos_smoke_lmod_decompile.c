/* decompiled with compiler spec: zos */

ulonglong entry(void)

{
  sbyte sVar1;
  ulonglong uVar2;
  
  uVar2 = subr();
  if (uVar2 == 0x2a) {
    sVar1 = 0;
  }
  else if ((longlong)uVar2 < 0) {
    if ((longlong)uVar2 < 0) {
      sVar1 = 1;
    }
    else {
      sVar1 = 2;
    }
  }
  else if (uVar2 < 0x2a) {
    sVar1 = 1;
  }
  else {
    sVar1 = 2;
  }
  if ((8U >> sVar1 & 2) == 0) {
    uVar2 = uVar2 & 0xffffffff00000000;
  }
  else {
    uVar2 = uVar2 & 0xffffffff00000000 | 1;
  }
  return uVar2;
}


