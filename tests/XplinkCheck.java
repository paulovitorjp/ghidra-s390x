// XplinkCheck.java — verify the zos_xplink compiler spec: cspec id,
// stack pointer register, and return address register.
import ghidra.app.script.GhidraScript;

public class XplinkCheck extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("language: " + currentProgram.getLanguage().getLanguageID());
        println("compiler: " + currentProgram.getCompilerSpec().getCompilerSpecID());
        println("stackpointer: " +
            currentProgram.getCompilerSpec().getStackPointer());
    }
}
