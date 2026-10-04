// s390x_pcode.cc — p-code oracle dumper for the s390x spec.
//
// Builds exactly like tests/s390x_decode.cc (same Ghidra decompiler
// C++ file set); see tests/validate_cond2.py.
//
// Usage: s390x_pcode <path-to-s390x.sla> <hex-bytes>
// Prints the disassembly line, then one line per emitted p-code op:
//   OP <opname> out=<varnode> in0=<varnode> ...
// Varnodes print as const:<value>:<size>, a register name (cc, r3, ...),
// or <space>:0x<offset>:<size>. Intra-instruction branch targets
// (CBRANCH/BRANCH in0 in the const space) print as const:<rel>:<size>, a
// SIGNED relative offset: the target is the op at index
// (index-of-this-op + rel).

#include "loadimage.hh"
#include "sleigh.hh"
#include "opcodes.hh"
#include <iostream>
#include <sstream>
#include <vector>
#include <cstdlib>
#include <cstdio>

using std::cerr;
using std::cout;
using std::endl;

namespace ghidra {

class HexLoadImage : public LoadImage {
  uintb baseaddr;
  int4 length;
  std::vector<uint1> data;
public:
  HexLoadImage(uintb ad, const std::vector<uint1> &bytes)
    : LoadImage("nofile"), baseaddr(ad), data(bytes), length((int4)bytes.size()) {}
  virtual void loadFill(uint1 *ptr, int4 size, const Address &addr) {
    uintb start = addr.getOffset();
    uintb max = baseaddr + (uintb)(length - 1);
    for (int4 i = 0; i < size; ++i) {
      uintb curoff = start + (uintb)i;
      if ((curoff < baseaddr) || (curoff > max)) { ptr[i] = 0; continue; }
      ptr[i] = data[(int4)(curoff - baseaddr)];
    }
  }
  virtual std::string getArchType(void) const { return "s390x_pcode"; }
  virtual void adjustVma(long) {}
};

class CaptureEmit : public AssemblyEmit {
public:
  std::string mnem, body;
  virtual void dump(const Address &addr, const std::string &m, const std::string &b) {
    mnem = m; body = b;
  }
};

class PcodeDumpEmit : public PcodeEmit {
public:
  Sleigh *trans;
  std::string fmt(const VarnodeData &v) {
    std::string sp = v.space->getName();
    if (sp == "const") {
      char buf[64];
      snprintf(buf, sizeof(buf), "const:%llu:%u", (unsigned long long)v.offset, v.size);
      return std::string(buf);
    }
    std::string rn;
    try { rn = trans->getRegisterName(v.space, v.offset, v.size); } catch (...) {}
    if (!rn.empty()) return rn;
    char buf[128];
    snprintf(buf, sizeof(buf), "%s:0x%llx:%u", sp.c_str(),
             (unsigned long long)v.offset, v.size);
    return std::string(buf);
  }
  virtual void dump(const Address &addr, OpCode opc, VarnodeData *outvar,
                    VarnodeData *vars, int4 isize) {
    cout << "OP " << get_opname(opc);
    if (outvar != (VarnodeData *)0) cout << " out=" << fmt(*outvar);
    for (int4 i = 0; i < isize; ++i) cout << " in" << i << "=" << fmt(vars[i]);
    cout << endl;
  }
};

} // namespace ghidra

int main(int argc, char **argv)
{
  using namespace ghidra;
  if (argc != 3) {
    cerr << "USAGE: " << argv[0] << " <s390x.sla> <hexbytes>" << endl;
    return 2;
  }
  std::string slafile(argv[1]);
  std::string hex(argv[2]);

  std::vector<uint1> bytes;
  for (size_t i = 0; i + 1 < hex.size(); i += 2)
    bytes.push_back((uint1)strtoul(hex.substr(i, 2).c_str(), 0, 16));
  if (bytes.empty()) { cout << "NODECODE empty-input" << endl; return 0; }

  AttributeId::initialize();
  ElementId::initialize();

  try {
    HexLoadImage loader(0x0, bytes);
    ContextInternal context;
    std::ostringstream ss;
    ss << "<sleigh>" << slafile << "</sleigh>";
    std::istringstream sleighfilename(ss.str());
    Sleigh trans(&loader, &context);

    DocumentStorage docstorage;
    Element *sleighroot = docstorage.parseDocument(sleighfilename)->getRoot();
    docstorage.registerTag(sleighroot);
    trans.initialize(docstorage);

    CaptureEmit emit;
    Address addr(trans.getDefaultCodeSpace(), 0);
    int4 length = 0;
    try {
      length = trans.printAssembly(emit, addr);
    }
    catch (const LowlevelError &e) {
      cout << "NODECODE lowlevel: " << e.explain << endl;
      return 0;
    }
    catch (...) {
      cout << "NODECODE match-exception" << endl;
      return 0;
    }
    if (length <= 0 || length != (int4)bytes.size()) {
      cout << "PARTIAL len=" << length << " mnem=" << emit.mnem
           << " body=" << emit.body << endl;
      return 0;
    }
    cout << "DISASM mnem=" << emit.mnem << " body=" << emit.body << endl;
    PcodeDumpEmit pemit;
    pemit.trans = &trans;
    try {
      trans.oneInstruction(pemit, addr);
    }
    catch (const LowlevelError &e) {
      cout << "PCODE-ERROR lowlevel: " << e.explain << endl;
      return 0;
    }
    catch (...) {
      cout << "PCODE-ERROR exception" << endl;
      return 0;
    }
  }
  catch (std::exception &e) {
    cout << "NODECODE " << e.what() << endl;
  }
  catch (...) {
    cout << "NODECODE unknown" << endl;
  }
  return 0;
}
