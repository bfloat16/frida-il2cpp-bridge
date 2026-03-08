from __future__ import annotations

from typing import Any, override

import argparse
import json
import re
from pathlib import Path

import colorama

from ..app import FridaIl2CppBridgeCommand


class DumpInitializeMethodMetadataRangeCommand(FridaIl2CppBridgeCommand[dict, dict]):
    NAME = "dump-immr"

    def __init__(self, *args: Any, **kwargs: Any):
        self._entries: list[dict[str, Any]] = []
        self._metadata_info: dict[str, Any] = {}
        self._module_base: int = 0
        super().__init__(*args, **kwargs)

    @property
    def agent_src(self) -> str:
        with open(
            Path(__file__).parent / "agent.js", mode="r", encoding="utf-8"
        ) as file:
            src = file.read()

        prelude = [
            f'globalThis.IL2CPP_IMMR_RVA = "{self.app.options.initialize_method_metadata_range_rva}";',
            f'globalThis.IL2CPP_METADATA_REGISTRATION_RVA = "{self.app.options.metadata_registration_rva}";',
            f'globalThis.IL2CPP_GLOBAL_METADATA_RVA = "{self.app.options.global_metadata_rva}";',
            f'globalThis.IL2CPP_GLOBAL_METADATA_HEADER_RVA = "{self.app.options.global_metadata_header_rva}";',
        ]

        if self.app.options.code_registration_rva is not None:
            prelude.append(
                f'globalThis.IL2CPP_CODE_REGISTRATION_RVA = "{self.app.options.code_registration_rva}";'
            )
        else:
            prelude.append("globalThis.IL2CPP_CODE_REGISTRATION_RVA = null;")

        return "\n".join(prelude) + "\n" + src

    @property
    def parser(self) -> dict:
        return dict(
            help="dumps metadata usages touched by MetadataCache::IntializeMethodMetadataRange (Unity 2018.4.36f1 path)",
            formatter_class=argparse.RawTextHelpFormatter,
        )

    @override
    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--initialize-method-metadata-range-rva",
            required=True,
            help="RVA of il2cpp::vm::MetadataCache::IntializeMethodMetadataRange",
        )
        parser.add_argument(
            "--metadata-registration-rva",
            required=True,
            help="RVA of g_MetadataRegistration",
        )
        parser.add_argument(
            "--global-metadata-rva",
            required=True,
            help="RVA of global variable s_GlobalMetadata (the pointer variable itself)",
        )
        parser.add_argument(
            "--global-metadata-header-rva",
            required=True,
            help="RVA of global variable s_GlobalMetadataHeader (the pointer variable itself)",
        )
        parser.add_argument(
            "--code-registration-rva",
            required=False,
            default=None,
            help="RVA of g_CodeRegistration (optional, for metadata labeling only)",
        )
        parser.add_argument(
            "--out-dir",
            type=Path,
            default=Path.cwd(),
            help="where to save the JSON metadata (defaults to current working dir)",
        )
        parser.add_argument(
            "--output-file",
            default="metadata.json",
            help="output file name (defaults to metadata.json)",
        )

    @override
    def on_send(self, payload: dict):
        payload_type = payload.get("type")

        if payload_type == "status":
            self.app.update_status(str(payload.get("message", "")))
            return

        if payload_type == "warning":
            self.app.print(
                f"{colorama.Style.BRIGHT}{colorama.Fore.YELLOW}Warning:{colorama.Style.RESET_ALL} {payload.get('message', '')}"
            )
            return

        if payload_type == "immr-chunk":
            self._entries.extend(payload.get("entries", []))
            self.app.update_status(
                f"Collecting metadata usage entries: {len(self._entries)}"
            )
            return

        if payload_type == "immr-meta":
            self._metadata_info = payload
            try:
                self._module_base = int(str(payload.get("module_base", "0x0")), 0)
            except Exception:
                self._module_base = 0
            return

        raise ValueError(f"Unknown payload type: {payload}")

    @override
    def on_exit(self, payload: dict):
        if error := payload.get("error"):
            raise RuntimeError(str(error))

        address_map = self._build_address_map()

        output_base_path = self.app.options.out_dir.resolve().absolute()
        output_base_path.mkdir(parents=True, exist_ok=True)
        output_path = output_base_path / self.app.options.output_file

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "addressMap": address_map,
                    "generator": {
                        "tool": "frida-il2cpp-bridge",
                        "command": self.NAME,
                        "capturedEntries": len(self._entries),
                        "elapsedMs": payload.get("elapsed_ms", 0),
                    },
                },
                f,
                ensure_ascii=False,
                indent=2,
            )

        self.app.print(
            f"Captured {colorama.Style.BRIGHT}{colorama.Fore.GREEN}{len(self._entries)}{colorama.Style.RESET_ALL} usage entries in {payload.get('elapsed_ms', 0) / 1000:.2f}s"
        )
        self.app.update_status(f"JSON metadata saved to {output_path}")

    def _build_address_map(self) -> dict[str, Any]:
        entries = sorted(
            self._entries,
            key=lambda e: int(str(e.get("slot_address", "0x0")), 0),
        )

        type_info_pointers: list[dict[str, str]] = []
        type_ref_pointers: list[dict[str, str]] = []
        method_info_pointers: list[dict[str, str]] = []
        fields: list[dict[str, str]] = []
        field_rvas: list[dict[str, str]] = []
        string_literals: list[dict[str, str]] = []

        for entry in entries:
            usage_type = int(entry.get("usage_type", 0))
            source_index = int(entry.get("source_index", 0))
            destination_index = int(entry.get("destination_index", 0))
            encoded_source_index = int(entry.get("encoded_source_index", 0))

            slot_address = str(entry.get("slot_address", "0x0"))
            value_address = str(entry.get("value_address", "0x0"))
            string_value = str(entry.get("string_value", ""))
            slot_rva = self._to_rva_hex(slot_address)
            value_rva = self._to_rva_hex_upper(value_address)

            if usage_type == 1:
                resolved_type_name = str(entry.get("resolved_type_name", "")).strip()
                type_info_pointers.append(
                    {
                        "virtualAddress": slot_rva,
                        "name": (
                            f"TypeInfo::{resolved_type_name}"
                            if resolved_type_name
                            else f"TypeInfo_{source_index}"
                        ),
                        "type": "struct Il2CppClass *",
                        "dotNetType": (
                            resolved_type_name
                            if resolved_type_name
                            else f"TypeIndex_{source_index}"
                        ),
                    }
                )
            elif usage_type == 2:
                resolved_type_ref_name = str(
                    entry.get("resolved_type_ref_name", "")
                ).strip()
                type_ref_pointers.append(
                    {
                        "virtualAddress": slot_rva,
                        "name": (
                            f"TypeRef::{resolved_type_ref_name}"
                            if resolved_type_ref_name
                            else f"TypeRef_{source_index}"
                        ),
                        "dotNetType": (
                            resolved_type_ref_name
                            if resolved_type_ref_name
                            else f"TypeIndex_{source_index}"
                        ),
                    }
                )
            elif usage_type in (3, 6):
                resolved_method_signature = str(
                    entry.get("resolved_method_signature", "")
                ).strip()
                method_info_pointers.append(
                    {
                        "virtualAddress": slot_rva,
                        "name": (
                            f"MethodInfo::{resolved_method_signature}"
                            if resolved_method_signature
                            else f"MethodInfo_{source_index}"
                        ),
                        "dotNetSignature": (
                            resolved_method_signature
                            if resolved_method_signature
                            else f"{'MethodDef' if usage_type == 3 else 'MethodRef'}Index_{source_index}"
                        ),
                    }
                )
            elif usage_type == 4:
                fields.append(
                    {
                        "virtualAddress": slot_rva,
                        "name": f"FieldInfo_{source_index}_Field",
                        "value": (
                            f"value={value_rva}; destinationIndex={destination_index}; "
                            f"encodedSourceIndex=0x{encoded_source_index:08X}"
                        ),
                    }
                )
            elif usage_type == 5:
                string_literals.append(
                    {
                        "virtualAddress": slot_rva,
                        "name": f"StringLiteral_{self._string_to_identifier(string_value)}",
                        "string": string_value,
                    }
                )
            elif usage_type == 7:
                field_rvas.append(
                    {
                        "virtualAddress": slot_rva,
                        "name": f"FieldRva_{source_index}_FieldRva",
                        "value": (
                            f"value={value_rva}; destinationIndex={destination_index}; "
                            f"encodedSourceIndex=0x{encoded_source_index:08X}"
                        ),
                    }
                )

        # shared_base.py assumes stringLiterals has at least one item.
        if len(string_literals) == 0:
            string_literals.append(
                {
                    "virtualAddress": "0x0",
                    "name": "StringLiteral_Empty",
                    "string": "",
                }
            )

        type_metadata: list[dict[str, str]] = []
        if metadata_registration_va := self._metadata_info.get("metadata_registration_va"):
            type_metadata.append(
                {
                    "virtualAddress": self._to_rva_hex(str(metadata_registration_va)),
                    "name": "g_MetadataRegistration",
                    "type": "struct Il2CppMetadataRegistration",
                }
            )
        if code_registration_va := self._metadata_info.get("code_registration_va"):
            type_metadata.append(
                {
                    "virtualAddress": self._to_rva_hex(str(code_registration_va)),
                    "name": "g_CodeRegistration",
                    "type": "struct Il2CppCodeRegistration",
                }
            )

        return {
            "functionAddresses": [],
            "methodDefinitions": [],
            "constructedGenericMethods": [],
            "customAttributesGenerators": [],
            "methodInvokers": [],
            "stringLiterals": string_literals,
            "typeInfoPointers": type_info_pointers,
            "typeRefPointers": type_ref_pointers,
            "methodInfoPointers": method_info_pointers,
            "fields": fields,
            "fieldRvas": field_rvas,
            "typeMetadata": type_metadata,
            "functionMetadata": [],
            "arrayMetadata": [],
            "apis": [],
            "exports": [],
            "symbols": [],
        }

    def _to_rva_hex(self, address: str) -> str:
        try:
            va = int(str(address), 0)
        except Exception:
            return "0x0"

        if va == 0:
            return "0x0"

        if self._module_base > 0 and va >= self._module_base:
            return hex(va - self._module_base)

        return hex(va)

    def _to_rva_hex_upper(self, address: str) -> str:
        try:
            va = int(str(address), 0)
        except Exception:
            return "0x0"

        if va == 0:
            return "0x0"

        if self._module_base > 0 and va >= self._module_base:
            rva = va - self._module_base
        else:
            rva = va

        return f"0x{rva:X}"

    def _string_to_identifier(self, value: str) -> str:
        s = value[:32].replace("*", "Ptr")
        escaped = []

        for c in s:
            code = ord(c)
            if code < 32 or code > 126:
                escaped.append(f"u{code:04X}")
            else:
                escaped.append(c)

        s = "".join(escaped)
        s = re.sub(r"[^a-zA-Z0-9_]", "_", s)

        if re.match(r"^[a-zA-Z_]", s) is None:
            s = "_" + s

        return s
