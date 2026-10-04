
/* WARNING: Unable to track spacebase fully for stack */
/* WARNING: Removing unreachable block (ram,0x00010080) */
/* WARNING: Removing unreachable block (ram,0x000100ae) */

ulong main(ulong param_1,ulong param_2)

{
  sbyte sVar1;
  ulong uVar2;
  undefined8 unaff_retaddr;
  long in_zero;
  
  *(undefined8 *)(&stack0x00000008 + in_zero) = unaff_retaddr;
  *(BADSPACEBASE **)(&stack0x00000010 + in_zero) = register0x00000078;
  uVar2 = sum(param_1 & 0xffffffff00000000 | 10);
  if (uVar2 == 0x32) {
    sVar1 = 0;
  }
  else if ((long)uVar2 < 0) {
    if ((long)uVar2 < 0) {
      sVar1 = 1;
    }
    else {
      sVar1 = 2;
    }
  }
  else if (uVar2 < 0x32) {
    sVar1 = 1;
  }
  else {
    sVar1 = 2;
  }
  if ((8U >> sVar1 & 2) == 0) {
    param_2 = param_2 & 0xffffffff00000000;
  }
  else {
    param_2 = param_2 & 0xffffffff00000000 | 1;
  }
  return param_2;
}



ulong sum(ulong param_1,ulong param_2)

{
  sbyte sVar1;
  ulong uVar2;
  ulong uVar3;
  
  param_2 = param_2 & 0xffffffff00000000;
  uVar3 = 1;
  do {
    param_2 = param_2 & 0xffffffff00000000 | (param_2 & 0xffffffff) + uVar3 & 0xffffffff;
    uVar3 = uVar3 + 1 & 0xffffffff;
    uVar2 = param_1 & 0xffffffff;
    if (uVar3 == uVar2) {
      sVar1 = 0;
    }
    else if (uVar3 >> 0x1f == uVar2 >> 0x1f) {
      if (uVar3 < uVar2) {
        sVar1 = 1;
      }
      else {
        sVar1 = 2;
      }
    }
    else if (uVar3 >> 0x1f == 1) {
      sVar1 = 1;
    }
    else {
      sVar1 = 2;
    }
  } while ((8U >> sVar1 & 0xd) != 0);
  return param_2;
}


