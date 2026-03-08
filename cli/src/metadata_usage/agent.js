/// <reference path="../../../lib/index.ts">/>

const t0 = new Date();
const gTypeNameCache = new Map();
const gClassTypeNameCache = new Map();
const gMethodNameCache = new Map();
const gMethodSignatureCache = new Map();

setTimeout(() => {
    Il2Cpp.perform(() => {
        send({
            action: "init",
            elapsed_ms: new Date() - t0,
            application: Il2Cpp.application,
            unityVersion: Il2Cpp.unityVersion
        });

        if (!Il2Cpp.unityVersion.startsWith("2018.4.36f1")) {
            send({
                type: "warning",
                message: `This command was designed for Unity 2018.4.36f1, current runtime is ${Il2Cpp.unityVersion}`
            });
        }

        const scanStart = new Date();

        const immrRva = parseRva(globalThis.IL2CPP_IMMR_RVA);
        const metadataRegistrationRva = parseRva(globalThis.IL2CPP_METADATA_REGISTRATION_RVA);
        const codeRegistrationRva = parseOptionalRva(globalThis.IL2CPP_CODE_REGISTRATION_RVA);
        const sGlobalMetadataVarRva = parseRva(globalThis.IL2CPP_GLOBAL_METADATA_RVA);
        const sGlobalMetadataHeaderVarRva = parseRva(globalThis.IL2CPP_GLOBAL_METADATA_HEADER_RVA);

        const moduleBase = Il2Cpp.module.base;
        const immrAddress = moduleBase.add(immrRva);
        const metadataRegistration = moduleBase.add(metadataRegistrationRva);
        const codeRegistration = codeRegistrationRva == null ? null : moduleBase.add(codeRegistrationRva);
        const sGlobalMetadataVar = moduleBase.add(sGlobalMetadataVarRva);
        const sGlobalMetadataHeaderVar = moduleBase.add(sGlobalMetadataHeaderVarRva);

        const metadataBase = sGlobalMetadataVar.readPointer();
        const metadataHeaderAddress = sGlobalMetadataHeaderVar.readPointer();

        if (metadataBase.isNull() || metadataHeaderAddress.isNull()) {
            throw new Error(
                `Runtime globals not initialized: s_GlobalMetadata=${metadataBase}, s_GlobalMetadataHeader=${metadataHeaderAddress}`
            );
        }

        // Runtime-only: do not parse/validate metadata file header.
        // Use exactly the offsets consumed by IntializeMethodMetadataRange in 2018.4.36f1.
        const metadataUsagePairsOffset = metadataHeaderAddress.add(0xf8).readU32();
        const metadataUsagePairsCountBytes = metadataHeaderAddress.add(0xfc).readU32();
        const pairsBase = metadataBase.add(metadataUsagePairsOffset);
        let pairsCount = metadataUsagePairsCountBytes >>> 3;

        const metadataRange = Process.findRangeByAddress(metadataBase);
        if (metadataRange != null) {
            const rangeBegin = metadataRange.base;
            const rangeEnd = metadataRange.base.add(metadataRange.size);
            if (pairsBase.compare(rangeBegin) < 0 || pairsBase.compare(rangeEnd) >= 0) {
                throw new Error(
                    `metadataUsagePairs base out of mapped metadata range: pairsBase=${pairsBase}, range=${rangeBegin}..${rangeEnd}`
                );
            }
            const maxPairs = Math.max(
                0,
                Math.floor(
                    (rangeEnd.sub(pairsBase).toUInt32()) /
                        8
                )
            );
            if (pairsCount > maxPairs) {
                pairsCount = maxPairs;
            }
        }

        send({
            type: "status",
            message: `Scanning metadata usage pairs (pairs=${pairsCount})`
        });

        // Dynamic part: actively execute IntializeMethodMetadataRange on all list ranges
        // so metadataUsages[destinationIndex] slots are initialized by the runtime itself.
        // We do not rely on metadataUsageLists.
        const initializeMethodMetadataRange = new NativeFunction(
            immrAddress,
            "void",
            [Process.pointerSize == 8 ? "uint64" : "uint32", "int32", "pointer", "int32"]
        );

        // utils::dynamic_array<Il2CppMetadataUsage> expectedUsages = empty
        // -> means "accept all usages"
        const expectedUsages = Memory.alloc(Process.pointerSize * 2);
        expectedUsages.writePointer(ptr(0));
        if (Process.pointerSize == 8) {
            expectedUsages.add(8).writeU64(0);
        } else {
            expectedUsages.add(4).writeU32(0);
        }

        if (pairsCount > 0) {
            // throwOnError = false, to keep scanning robust like static tooling.
            initializeMethodMetadataRange(0, pairsCount, expectedUsages, 0);
        }

        const metadataUsages = resolveMetadataUsagesArray(metadataRegistration);
        const usagesByDestinationIndex = new Map();
        for (let i = 0; i < pairsCount; i++) {
            const pairAddress = pairsBase.add(i * 8);
            const destinationIndex = pairAddress.readU32();
            const encodedSourceIndex = pairAddress.add(4).readU32();

            if (!usagesByDestinationIndex.has(destinationIndex)) {
                usagesByDestinationIndex.set(destinationIndex, encodedSourceIndex);
            }
        }

        send({
            type: "immr-meta",
            module_base: moduleBase.toString(),
            metadata_registration_va: metadataRegistration.toString(),
            code_registration_va: codeRegistration?.toString() ?? null,
            metadata_usages_offset: "0x" + metadataUsages.offset.toString(16),
            metadata_base: metadataBase.toString(),
            metadata_header: metadataHeaderAddress.toString(),
            metadata_usage_pairs_count: pairsCount,
            distinct_destinations_count: usagesByDestinationIndex.size
        });

        const entries = [];
        for (const [destinationIndex, encodedSourceIndex] of usagesByDestinationIndex.entries()) {
            const usageType = (encodedSourceIndex >>> 29) & 0x7;
            const sourceIndex = encodedSourceIndex & 0x1fffffff;

            if (usageType == 0) {
                continue;
            }

            let slotAddress = ptr(0);
            let valueAddress = ptr(0);
            try {
                slotAddress = metadataUsages.array.add(destinationIndex * Process.pointerSize).readPointer();
                if (!slotAddress.isNull()) {
                    valueAddress = slotAddress.readPointer();
                }
            } catch (_) {
                continue;
            }

            entries.push({
                usage_type: usageType,
                source_index: sourceIndex,
                destination_index: destinationIndex,
                encoded_source_index: encodedSourceIndex,
                slot_address: slotAddress.toString(),
                value_address: valueAddress.toString(),
                string_value: usageType == 5 ? tryReadIl2CppString(valueAddress) : "",
                resolved_type_name:
                    usageType == 1 ? tryResolveClassTypeDisplayName(valueAddress) : "",
                resolved_type_ref_name:
                    usageType == 2 ? tryResolveTypeDisplayName(valueAddress) : "",
                resolved_method_signature:
                    usageType == 3 || usageType == 6
                        ? tryResolveMethodDisplaySignature(valueAddress)
                        : ""
            });
        }

        const chunkSize = 1024;
        const totalChunks = Math.max(1, Math.ceil(entries.length / chunkSize));
        for (let i = 0; i < totalChunks; i++) {
            send({
                type: "immr-chunk",
                chunk_index: i,
                total_chunks: totalChunks,
                entries: entries.slice(i * chunkSize, (i + 1) * chunkSize)
            });
        }

        send({
            action: "exit",
            elapsed_ms: new Date() - scanStart
        });
    }).catch(e => {
        send({
            action: "exit",
            error: e?.stack ?? e?.message ?? `${e}`
        });
    });
});

function parseRva(value) {
    if (value == null) {
        throw new Error("Missing required RVA value");
    }

    if (typeof value == "number") {
        return value;
    }

    const s = `${value}`.trim().toLowerCase();
    return s.startsWith("0x") ? parseInt(s, 16) : parseInt(s, 10);
}

function parseOptionalRva(value) {
    if (value == null || value === "null" || value === "") {
        return null;
    }

    return parseRva(value);
}

function resolveMetadataUsagesArray(metadataRegistration) {
    const candidates = Process.pointerSize == 8 ? [0x78, 0x80] : [0x3c, 0x40];

    for (const offset of candidates) {
        try {
            const array = metadataRegistration.add(offset).readPointer();
            if (array.isNull()) {
                continue;
            }

            array.readPointer();
            return { array, offset };
        } catch (_) {
        }
    }

    throw new Error("Could not resolve metadataUsages pointer array from g_MetadataRegistration");
}

function tryReadIl2CppString(valueAddress) {
    if (valueAddress.isNull()) {
        return "";
    }

    try {
        const lengthOffset = Process.pointerSize * 2;
        const length = valueAddress.add(lengthOffset).readS32();
        if (length < 0 || length > 0x4000) {
            return "";
        }

        return valueAddress.add(lengthOffset + 4).readUtf16String(length) ?? "";
    } catch (_) {
        return "";
    }
}

function tryResolveClassTypeDisplayName(classAddress) {
    if (classAddress.isNull()) {
        return "";
    }

    const cacheKey = classAddress.toString();
    if (gClassTypeNameCache.has(cacheKey)) {
        return gClassTypeNameCache.get(cacheKey);
    }

    try {
        const typeAddress = Il2Cpp.exports.classGetType(classAddress);
        const displayName = tryResolveTypeDisplayName(typeAddress);
        if (displayName.length > 0) {
            gClassTypeNameCache.set(cacheKey, displayName);
            return displayName;
        }

        const name = readUtf8OrEmpty(Il2Cpp.exports.classGetName(classAddress));
        const namespaze = readUtf8OrEmpty(Il2Cpp.exports.classGetNamespace(classAddress));
        const fallback = namespaze.length == 0 ? name : `${namespaze}.${name}`;
        gClassTypeNameCache.set(cacheKey, fallback);
        return fallback;
    } catch (_) {
        return "";
    }
}

function tryResolveMethodName(methodAddress) {
    if (methodAddress.isNull()) {
        return "";
    }

    const cacheKey = methodAddress.toString();
    if (gMethodNameCache.has(cacheKey)) {
        return gMethodNameCache.get(cacheKey);
    }

    try {
        const name = readUtf8OrEmpty(Il2Cpp.exports.methodGetName(methodAddress));
        gMethodNameCache.set(cacheKey, name);
        return name;
    } catch (_) {
        return "";
    }
}

function tryResolveMethodDisplaySignature(methodAddress) {
    if (methodAddress.isNull()) {
        return "";
    }

    const cacheKey = methodAddress.toString();
    if (gMethodSignatureCache.has(cacheKey)) {
        return gMethodSignatureCache.get(cacheKey);
    }

    try {
        const methodNameRaw = tryResolveMethodName(methodAddress);
        if (methodNameRaw.length == 0) {
            return "";
        }

        const classAddress = Il2Cpp.exports.methodGetClass(methodAddress);
        const classDisplayName = classAddress.isNull()
            ? ""
            : tryResolveClassTypeDisplayName(classAddress);
        const methodName = normalizeMethodName(methodNameRaw, classDisplayName);
        const parameterTypes = [];

        const parameterCount = Il2Cpp.exports.methodGetParameterCount(methodAddress);
        for (let i = 0; i < parameterCount; i++) {
            try {
                const parameterType = Il2Cpp.exports.methodGetParameterType(methodAddress, i);
                const parameterDisplayName = tryResolveTypeDisplayName(parameterType);
                parameterTypes.push(parameterDisplayName.length > 0 ? parameterDisplayName : "<?>");
            } catch (_) {
                parameterTypes.push("<?>");
            }
        }

        const paramsPart = parameterTypes.length == 0 ? "void" : parameterTypes.join(",");
        const resolved = classDisplayName.length == 0
            ? `${methodName}(${paramsPart})`
            : `${classDisplayName}::${methodName}(${paramsPart})`;

        gMethodSignatureCache.set(cacheKey, resolved);
        return resolved;
    } catch (_) {
        return "";
    }
}

function readUtf8OrEmpty(pointerValue) {
    if (pointerValue == null || pointerValue.isNull()) {
        return "";
    }

    try {
        return pointerValue.readUtf8String() ?? "";
    } catch (_) {
        return "";
    }
}

function tryResolveTypeDisplayName(typeAddress) {
    if (typeAddress == null || typeAddress.isNull()) {
        return "";
    }

    const cacheKey = typeAddress.toString();
    if (gTypeNameCache.has(cacheKey)) {
        return gTypeNameCache.get(cacheKey);
    }

    try {
        const ownedName = Il2Cpp.exports.typeGetName(typeAddress);
        const displayName = readUtf8OrEmpty(ownedName);
        tryFreeOwnedString(ownedName);
        gTypeNameCache.set(cacheKey, displayName);
        return displayName;
    } catch (_) {
        return "";
    }
}

function tryFreeOwnedString(pointerValue) {
    if (pointerValue == null || pointerValue.isNull()) {
        return;
    }

    try {
        Il2Cpp.exports.free(pointerValue);
    } catch (_) {
    }
}

function normalizeMethodName(methodNameRaw, classDisplayName) {
    if (methodNameRaw == ".ctor") {
        const simpleTypeName = extractSimpleTypeName(classDisplayName);
        return simpleTypeName.length > 0 ? simpleTypeName : "ctor";
    }

    if (methodNameRaw == ".cctor") {
        return "cctor";
    }

    return methodNameRaw;
}

function extractSimpleTypeName(typeDisplayName) {
    if (!typeDisplayName || typeDisplayName.length == 0) {
        return "";
    }

    let index = typeDisplayName.lastIndexOf(".");
    if (index == -1) {
        index = typeDisplayName.lastIndexOf("+");
    }
    if (index == -1) {
        index = typeDisplayName.lastIndexOf("/");
    }

    return index >= 0 ? typeDisplayName.substring(index + 1) : typeDisplayName;
}
