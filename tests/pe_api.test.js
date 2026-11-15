#!/usr/bin/env node
"use strict";

const assert = require("assert");
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const ROOT = path.resolve(__dirname, "..");
const SAMPLES = path.join(__dirname, "samples");

function readFile(filePath) {
    return fs.readFileSync(filePath, "utf8");
}

function shannonEntropy(buffer) {
    if (buffer.length === 0) {
        return 0;
    }

    const frequencies = new Array(256).fill(0);

    for (let i = 0; i < buffer.length; i++) {
        frequencies[buffer[i]]++;
    }

    let entropy = 0;

    for (let i = 0; i < frequencies.length; i++) {
        if (frequencies[i] === 0) {
            continue;
        }

        const probability = frequencies[i] / buffer.length;
        entropy -= probability * Math.log2(probability);
    }

    return entropy;
}

function parsePE(filePath) {
    const data = fs.readFileSync(filePath);
    const peOffset = data.readUInt32LE(0x3c);

    assert.strictEqual(data.toString("latin1", peOffset, peOffset + 4), "PE\u0000\u0000");

    const numberOfSections = data.readUInt16LE(peOffset + 6);
    const optionalHeaderSize = data.readUInt16LE(peOffset + 20);
    const optionalHeaderOffset = peOffset + 24;
    const magic = data.readUInt16LE(optionalHeaderOffset);
    const is64 = magic === 0x20b;
    const entryPointRva = data.readUInt32LE(optionalHeaderOffset + 16);
    const sectionTableOffset = optionalHeaderOffset + optionalHeaderSize;
    const sections = [];

    for (let i = 0; i < numberOfSections; i++) {
        const offset = sectionTableOffset + i * 40;
        const nameBytes = data.subarray(offset, offset + 8);
        const nullOffset = nameBytes.indexOf(0);
        const name = nameBytes.toString("latin1", 0, nullOffset === -1 ? 8 : nullOffset);

        sections.push({
            name,
            virtualSize: data.readUInt32LE(offset + 8),
            virtualAddress: data.readUInt32LE(offset + 12),
            rawSize: data.readUInt32LE(offset + 16),
            rawOffset: data.readUInt32LE(offset + 20),
            characteristics: data.readUInt32LE(offset + 36),
        });
    }

    function rvaToOffset(rva) {
        for (const section of sections) {
            const extent = Math.max(section.virtualSize, section.rawSize);

            if (rva >= section.virtualAddress && rva < section.virtualAddress + extent) {
                const offset = section.rawOffset + rva - section.virtualAddress;

                if (offset >= section.rawOffset && offset < section.rawOffset + section.rawSize) {
                    return offset;
                }
            }
        }

        return -1;
    }

    const importDirectoryOffset = optionalHeaderOffset + (is64 ? 112 : 96);
    const importRva = data.readUInt32LE(importDirectoryOffset + 8);
    const imports = [];
    let descriptorOffset = importRva ? rvaToOffset(importRva) : -1;

    while (descriptorOffset !== -1 && descriptorOffset + 20 <= data.length) {
        const originalFirstThunk = data.readUInt32LE(descriptorOffset);
        const nameRva = data.readUInt32LE(descriptorOffset + 12);

        if (originalFirstThunk === 0 && nameRva === 0) {
            break;
        }

        const nameOffset = rvaToOffset(nameRva);
        const nullOffset = data.indexOf(0, nameOffset);
        const name = data.toString("latin1", nameOffset, nullOffset);
        const thunkOffset = rvaToOffset(originalFirstThunk);
        const functions = [];
        const thunkSize = is64 ? 8 : 4;
        let currentThunkOffset = thunkOffset;

        while (currentThunkOffset !== -1) {
            const value = is64
                ? data.readBigUInt64LE(currentThunkOffset)
                : BigInt(data.readUInt32LE(currentThunkOffset));
            const ordinalMask = is64 ? 1n << 63n : 1n << 31n;

            if (value === 0n) {
                break;
            }

            if ((value & ordinalMask) === 0n) {
                const functionOffset = rvaToOffset(Number(value & 0x7fffffffn));
                const functionNullOffset = data.indexOf(0, functionOffset + 2);
                functions.push(data.toString("latin1", functionOffset + 2, functionNullOffset));
            }

            currentThunkOffset += thunkSize;
        }

        imports.push({ name, functions });
        descriptorOffset += 20;
    }

    return {
        data,
        is64,
        entryPointRva,
        sections,
        imports,
    };
}

function parseSignature(signature) {
    const tokens = [];
    const text = signature.replace(/\s+/g, "");
    let index = 0;

    while (index < text.length) {
        if (text[index] === "'") {
            const end = text.indexOf("'", index + 1);

            if (end === -1) {
                return null;
            }

            const value = text.slice(index + 1, end);
            for (let i = 0; i < value.length; i++) {
                tokens.push(value.charCodeAt(i));
            }
            index = end + 1;
            continue;
        }

        if (text.slice(index, index + 2) === "??" || text.slice(index, index + 2) === "..") {
            tokens.push(-1);
            index += 2;
            continue;
        }

        const byteText = text.slice(index, index + 2);

        if (!/^[0-9a-fA-F]{2}$/.test(byteText)) {
            return null;
        }

        tokens.push(parseInt(byteText, 16));
        index += 2;
    }

    return tokens;
}

function matchSignatureAt(data, offset, tokens) {
    if (offset < 0 || offset + tokens.length > data.length) {
        return false;
    }

    for (let i = 0; i < tokens.length; i++) {
        if (tokens[i] !== -1 && data[offset + i] !== tokens[i]) {
            return false;
        }
    }

    return true;
}

function findSignature(data, offset, size, signature) {
    const tokens = parseSignature(signature);

    if (!tokens) {
        return -1;
    }

    const end = Math.min(data.length, offset + size);

    for (let position = offset; position + tokens.length <= end; position++) {
        if (matchSignatureAt(data, position, tokens)) {
            return position;
        }
    }

    return -1;
}

function createEnvironment(parsed) {
    const calls = { calculateEntropy: 0 };
    const sectionBuffer = (index) => {
        const section = parsed.sections[index];
        return parsed.data.subarray(section.rawOffset, section.rawOffset + section.rawSize);
    };

    const pe = {
        getSize: () => parsed.data.length,
        getNumberOfSections: () => parsed.sections.length,
        getSectionName: (index) => parsed.sections[index] ? parsed.sections[index].name : "",
        getSectionVirtualSize: (index) => parsed.sections[index] ? parsed.sections[index].virtualSize : 0,
        getSectionVirtualAddress: (index) => parsed.sections[index] ? parsed.sections[index].virtualAddress : 0,
        getSectionFileSize: (index) => parsed.sections[index] ? parsed.sections[index].rawSize : 0,
        getSectionFileOffset: (index) => parsed.sections[index] ? parsed.sections[index].rawOffset : 0,
        getSectionCharacteristics: (index) => parsed.sections[index] ? parsed.sections[index].characteristics : 0,
        getSectionNumber: (name) => parsed.sections.findIndex((section) => section.name === name),
        isSectionNamePresent: (name) => parsed.sections.some((section) => section.name === name),
        getEntryPointSection: () => parsed.sections.findIndex((section) => {
            const extent = Math.max(section.virtualSize, section.rawSize);
            return parsed.entryPointRva >= section.virtualAddress &&
                parsed.entryPointRva < section.virtualAddress + extent;
        }),
        getImportSection: () => -1,
        getNumberOfImports: () => parsed.imports.length,
        getImportLibraryName: (index) => parsed.imports[index] ? parsed.imports[index].name : "",
        getNumberOfImportThunks: (index) => parsed.imports[index] ? parsed.imports[index].functions.length : 0,
        getImportFunctionName: (importIndex, functionIndex) => {
            const library = parsed.imports[importIndex];
            return library && library.functions[functionIndex] !== undefined
                ? library.functions[functionIndex]
                : "";
        },
        isLibraryPresent: (name) => {
            const lowerName = name.toLowerCase();
            return parsed.imports.some((library) => library.name.toLowerCase() === lowerName);
        },
        isLibraryFunctionPresent: (libraryName, functionName) => {
            const lowerLibrary = libraryName.toLowerCase();
            const lowerFunction = functionName.toLowerCase();
            return parsed.imports.some((library) => library.name.toLowerCase() === lowerLibrary &&
                library.functions.some((name) => name.toLowerCase() === lowerFunction));
        },
        isNet: () => false,
        isSignedFile: () => false,
        is64: () => parsed.is64,
        getNumberOfExportFunctions: () => 0,
        getExportFunctionName: () => "",
        getNextNamedExportFunctionIndex: () => -1,
        getNumberOfResources: () => 0,
        getResourceIdByNumber: () => 0,
        getResourceNameByNumber: () => "",
        getResourceOffsetByNumber: () => 0,
        getResourceSizeByNumber: () => 0,
        getResourceTypeByNumber: () => "",
        isResourceNamePresent: () => false,
        calculateEntropy: (offset, size) => {
            calls.calculateEntropy++;
            return shannonEntropy(parsed.data.subarray(offset, offset + size));
        },
        compare: (signature, offset) => {
            const tokens = parseSignature(signature);
            return tokens ? matchSignatureAt(parsed.data, offset || 0, tokens) : false;
        },
        isSignaturePresent: (offset, size, signature) =>
            findSignature(parsed.data, offset, size, signature) !== -1,
        isSignatureInSectionPresent: (index, signature) => {
            const section = parsed.sections[index];
            return section ? findSignature(parsed.data, section.rawOffset, section.rawSize, signature) !== -1 : false;
        },
    };

    const sandbox = {
        PE: pe,
        console,
        bDetected: false,
        sName: "",
        sVersion: "",
        sOptions: "",
        sType: "",
        sLang: "",
        sLangVersion: "",
        __meta: null,
        _log: function () {},
    };

    sandbox.meta = (type, name) => {
        sandbox.__meta = { type, name };
    };
    sandbox.result = () => sandbox.bDetected === true;

    const context = vm.createContext(sandbox);

    vm.runInContext(readFile(path.join(ROOT, "db/PE/_init")), context, {
        filename: "db/PE/_init",
    });

    return {
        pe,
        context,
        calls,
        sectionBuffer,
    };
}

function evaluateRule(environment, rulePath) {
    vm.runInContext(readFile(rulePath), environment.context, { filename: rulePath });
    return environment.context.detect();
}

function assertApproximately(actual, expected, tolerance, message) {
    assert.ok(Math.abs(actual - expected) <= tolerance, `${message}: ${actual} != ${expected}`);
}

function testSectionEntropy() {
    const parsed = parsePE(path.join(SAMPLES, "pezor-x64.exe"));
    const environment = createEnvironment(parsed);
    const textIndex = parsed.sections.findIndex((section) => section.name === ".text");
    const expected = shannonEntropy(environment.sectionBuffer(textIndex));

    assertApproximately(environment.pe.getSectionEntropy(textIndex), expected, 1e-12, "raw section entropy");
    assertApproximately(environment.pe.getSectionEntropy(".text"), expected, 1e-12, "named section entropy");
    assertApproximately(environment.pe.section[textIndex].getEntropy(), expected, 1e-12, "Section.getEntropy");
    assert.strictEqual(environment.pe.getSectionEntropy(999), -1);
    assert.strictEqual(environment.pe.getSectionEntropy("missing"), -1);

    const callsAfterFirstCalculation = environment.calls.calculateEntropy;
    environment.pe.getSectionEntropy(textIndex);
    environment.pe.getSectionEntropy(".text");
    assert.strictEqual(environment.calls.calculateEntropy, callsAfterFirstCalculation, "entropy cache");
}

function testImportTable() {
    const parsed = parsePE(path.join(SAMPLES, "pezor-x64.exe"));
    const environment = createEnvironment(parsed);
    const table = environment.pe.getImportTable();

    assert.strictEqual(table.length, parsed.imports.length);
    assert.strictEqual(table[0].Name, parsed.imports[0].name);
    assert.strictEqual(table[0].Library, parsed.imports[0].name);
    assert.deepStrictEqual(Array.from(table[0].Functions), parsed.imports[0].functions);
    assert.strictEqual(table[0].FunctionCount, parsed.imports[0].functions.length);
    assert.strictEqual(table["KERNEL32.dll"], table["kernel32.dll"]);
    assert.strictEqual(table["kernel32.dll"].Name, "KERNEL32.dll");
    assert.strictEqual(environment.pe.getImportTable(), table);
}

function testCompositeConditions() {
    const parsed = parsePE(path.join(SAMPLES, "pezor-x64.exe"));
    const environment = createEnvironment(parsed);
    const pe = environment.pe;
    const textSection = parsed.sections.find((section) => section.name === ".text");
    const textEntropy = shannonEntropy(environment.sectionBuffer(parsed.sections.indexOf(textSection)));
    const textBytes = environment.sectionBuffer(parsed.sections.indexOf(textSection))
        .subarray(0, 4)
        .toString("hex")
        .toUpperCase();

    assert.strictEqual(pe.matchSignatures({ section: ".buildid" }), true);
    assert.strictEqual(pe.matchSignatures({ section: ".missing" }), false);
    assert.strictEqual(pe.matchSignatures({ sectionName: ".buildid" }), true);
    assert.strictEqual(pe.matchSignatures({ all: [{ section: ".text" }, { section: ".rdata" }] }), true);
    assert.strictEqual(pe.matchSignatures({ any: [{ section: ".missing" }, { section: ".text" }] }), true);
    assert.strictEqual(pe.matchSignatures({ none: [{ section: ".missing" }] }), true);
    assert.strictEqual(pe.matchSignatures({ none: [{ section: ".text" }] }), false);
    assert.strictEqual(pe.matchSignatures({ not: { section: ".missing" } }), true);
    assert.strictEqual(pe.matchSignatures(["any", { section: ".missing" }, { section: ".text" }]), true);
    assert.strictEqual(pe.matchSignatures([{ section: ".text" }, { section: ".buildid" }]), true);
    assert.strictEqual(pe.matchSignatures([]), false);
    assert.strictEqual(pe.matchSignatures({ all: [] }), false);
    assert.strictEqual(pe.matchSignatures({ library: "KERNEL32.dll" }), true);
    assert.strictEqual(pe.matchSignatures({ library: "kernel32.dll", function: "VirtualAllocEx" }), true);
    assert.strictEqual(pe.matchSignatures({ import: "KERNEL32.dll", function: "NoSuchFunction" }), false);
    assert.strictEqual(pe.matchSignatures({ maxImports: 10 }), true);
    assert.strictEqual(pe.matchSignatures({ maxImports: 2 }), false);
    assert.strictEqual(pe.matchSignatures({ maxImportFunctions: 64 }), true);
    assert.strictEqual(pe.matchSignatures({ maxImportFunctions: 4 }), false);
    assert.strictEqual(pe.matchSignatures({ minSections: 2, maxSections: 8 }), true);
    assert.strictEqual(pe.matchSignatures({ maxSections: 6 }), false);
    assert.strictEqual(pe.matchSignatures({
        entropy: {
            section: ".text",
            min: textEntropy - 0.1,
            max: textEntropy + 0.1,
        },
    }), true);
    assert.strictEqual(pe.matchSignatures({ section: ".text", entropyMin: 7 }), false);
    assert.strictEqual(pe.matchSignatures({ section: ".text", library: "KERNEL32.dll" }), true);
    assert.strictEqual(pe.matchSignatures({
        section: ".text",
        library: "KERNEL32.dll",
        entropyMin: 7,
    }), false);
    assert.strictEqual(pe.matchSignatures({ signature: "4D5A", offset: 0 }), true);
    assert.strictEqual(pe.matchSignatures({ signature: "4D5A" }), true);
    assert.strictEqual(pe.matchSignatures({ signature: "4D5A", size: 2 }), true);
    assert.strictEqual(pe.matchSignatures({ signature: "50450000", size: 2 }), false);
    assert.strictEqual(pe.matchSignatures({ signature: textBytes, section: ".text" }), true);
    assert.strictEqual(pe.matchSignatures({
        signature: "C0DEC0DEC0DEC0DEC0DEC0DEC0DEC0DEC0DEC0DEC0DEC0DEC0DEC0DEC0DEC0DE",
        section: ".text",
    }), false);
    assert.strictEqual(pe.matchSignatures({ pattern: "4D5A", offset: 0 }), true);
    assert.strictEqual(pe.matchSignatures({ compare: "4D5A", offset: 0 }), true);
    assert.strictEqual(pe.matchSignatures({ signature: "4D5A", offset: -1 }), false);
    assert.strictEqual(pe.matchSignatures(null), false);
    assert.strictEqual(pe.matchSignatures(""), false);
    assert.strictEqual(pe.matchSignatures({}), false);
    assert.strictEqual(pe.matchSignatures({ not: {} }), false);
    assert.strictEqual(pe.matchSignatures({ none: [{}] }), false);
    assert.strictEqual(pe.matchSignatures(["not"]), false);
    assert.strictEqual(pe.matchSignatures({ all: [{ section: ".text" }], none: [{ section: ".text" }] }), false);
    assert.strictEqual(pe.isSignatureCombinationPresent({ section: ".text" }), true);
}

function testPEzorRule() {
    const rulePath = path.join(ROOT, "db/PE/packer_PEzor.2.sg");

    for (const sample of ["pezor-x64.exe", "pezor-x86.exe"]) {
        const environment = createEnvironment(parsePE(path.join(SAMPLES, sample)));
        assert.strictEqual(evaluateRule(environment, rulePath), true, `PEzor rule: ${sample}`);
    }

    const cleanEnvironment = createEnvironment(parsePE(path.join(SAMPLES, "clean-mingw-x64.exe")));
    assert.strictEqual(evaluateRule(cleanEnvironment, rulePath), false, "PEzor rule false positive");
}

function testGenericRule() {
    const rulePath = path.join(ROOT, "db/PE/packer_Generic_Entropy_Import.2.sg");
    const packedEnvironment = createEnvironment(parsePE(path.join(SAMPLES, "generic-packed-pe.exe")));

    assert.strictEqual(packedEnvironment.pe.getImportTable().length, 0);
    assert.ok(packedEnvironment.pe.getSectionEntropy(".text") >= 7);
    assert.strictEqual(evaluateRule(packedEnvironment, rulePath), true, "generic packed sample");

    const cleanEnvironment = createEnvironment(parsePE(path.join(SAMPLES, "clean-mingw-x64.exe")));
    assert.strictEqual(evaluateRule(cleanEnvironment, rulePath), false, "generic rule false positive");

    const pezorEnvironment = createEnvironment(parsePE(path.join(SAMPLES, "pezor-x64.exe")));
    assert.strictEqual(evaluateRule(pezorEnvironment, rulePath), false, "generic rule known packer exclusion");
}

function main() {
    testSectionEntropy();
    testImportTable();
    testCompositeConditions();
    testPEzorRule();
    testGenericRule();
    console.log("PE API tests passed");
}

main();
