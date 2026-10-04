#!/bin/bash
# build_elf_reloc.sh -- compile the s390x ELF relocation handler and install
# the jar into the local Ghidra processor module. Re-run after any change.
# The handler is discovered automatically by Ghidra's ClassSearcher
# (ExtensionPoint); no registration file is needed.
set -e
PROJ=/home/hatch/workspace/zarch-sleigh
G=/home/hatch/workspace/ghidra-dist/ghidra_12.1.3_PUBLIC
CP=$(ls $G/Ghidra/Framework/*/lib/*.jar $G/Ghidra/Features/*/lib/*.jar | tr '\n' ':')
rm -rf $PROJ/loaders/build-elfreloc
mkdir -p $PROJ/loaders/build-elfreloc
JDIR=~/workspace/java/jdk-21.0.12.1+1/bin
$JDIR/javac -nowarn -cp "$CP" -d $PROJ/loaders/build-elfreloc \
    $PROJ/loaders/src/ghidra/app/util/bin/format/elf/relocation/*.java
mkdir -p $G/Ghidra/Processors/s390x/lib
$JDIR/jar cf $G/Ghidra/Processors/s390x/lib/s390x-elf-reloc.jar \
    -C $PROJ/loaders/build-elfreloc .
echo "installed: $G/Ghidra/Processors/s390x/lib/s390x-elf-reloc.jar"
unzip -l $G/Ghidra/Processors/s390x/lib/s390x-elf-reloc.jar | grep class
