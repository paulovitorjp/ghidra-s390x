// s390x_decode.cc — minimal SLEIGH disassembly oracle for the s390x spec.
//
// Usage: s390x_decode <path-to-s390x.sla> <hex-bytes>
// Prints one line:
//   OK len=<n> mnem=<mnemonic> body=<operand text>     (exact full-length decode)
//   PARTIAL len=<n> mnem=... body=...                  (decoded but wrong length)
//   NODECODE <reason>                                   (no constructor matched)
//
// Exit code is always 0; failures are reported in the output line so the
// Python driver can classify every corpus vector.

#include "loadimage.hh"
#include "sleigh.hh"
#include <iostream>
#include <sstream>
#include <vector>
#include <cstdlib>

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
  virtual std::string getArchType(void) const { return "s390x_decode"; }
  virtual void adjustVma(long) {}
};

class CaptureEmit : public AssemblyEmit {
public:
  std::string mnem, body;
  virtual void dump(const Address &addr, const std::string &m, const std::string &b) {
    mnem = m; body = b;
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
    catch (std::exception &e) {
      cout << "NODECODE match-exception" << endl;
      return 0;
    }
    catch (...) {
      cout << "NODECODE match-unknown" << endl;
      return 0;
    }
    if (length <= 0 || length != (int4)bytes.size()) {
      cout << "PARTIAL len=" << length << " mnem=" << emit.mnem
           << " body=" << emit.body << endl;
      return 0;
    }
    cout << "OK len=" << length << " mnem=" << emit.mnem
         << " body=" << emit.body << endl;
  }
  catch (std::exception &e) {
    cout << "NODECODE " << e.what() << endl;
  }
  catch (...) {
    cout << "NODECODE unknown" << endl;
  }
  return 0;
}
