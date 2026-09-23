"""Expose source information retained in bytecode without inventing identifiers."""
from bisect import bisect_right


def source_location(packed):
    return {"line": packed & 0xfffff, "column": packed >> 20} if packed else None


def script_functions(module):
    """Include initializer and behavior bodies, deduplicated by identity."""
    seen = set()
    candidates = list(module.script_functions) + list(module.global_functions)
    candidates += [g.init_func for g in module.globals]
    for cls in module.classes:
        candidates += cls.methods + cls.constructors + cls.factories + cls.vft
        candidates.append(cls.destructor)
    for function in candidates:
        if function is not None and function.bytecode and id(function) not in seen:
            seen.add(id(function))
            yield function


def function_evidence(function):
    debug = function.has_debug_info
    section_changes = sorted(zip(function.sections[::2], function.sections[1::2])) if debug else []
    positions = [pos for pos, name in section_changes]
    mappings = []
    if debug:
        for pos, packed in zip(function.line_numbers[::2], function.line_numbers[1::2]):
            index = bisect_right(positions, pos) - 1
            section = section_changes[index][1] if index >= 0 else function.script_section
            mappings.append({"bytecode_dword": pos, "section": section or None,
                             **(source_location(packed) or {"line": 0, "column": 0})})
    owner = function.object_type or function.parent_class
    return {
        "signature": function.signature(),
        "namespace": owner.namespace_ if owner else function.namespace_,
        "owner": owner.format_name() if owner else None,
        "saved_source_section": function.script_section or None if debug else None,
        "saved_declaration": source_location(function.declared_at) if debug else None,
        "saved_parameter_names": list(function.param_names) if debug else [],
        "parameters": [{"type": dt.format(),
                        "direction_flags": function.in_out_flags[i] if i < len(function.in_out_flags) else 0,
                        "saved_default": function.default_args[i] if i < len(function.default_args) else None}
                       for i, dt in enumerate(function.param_types)],
        "locals": [{"saved_name": var.name or None if debug else None,
                    "type": var.type.format(), "stack_offset": var.stack_offset,
                    "on_heap": var.on_heap,
                    "declaration_bytecode_dword": var.declared_at if debug else None}
                   for var in function.variables],
        "source_line_mappings": mappings,
        "saved_scope_and_lifetime_markers": [
            {"bytecode_dword": pos, "stack_offset": offset, "option": option}
            for pos, offset, option in function.obj_variable_info],
        "call_signatures": sorted({ins.func_ref.signature(False) for ins in function.bytecode
                                   if ins.func_ref is not None}),
    }


def recovery_evidence(module):
    functions = [function_evidence(function) for function in script_functions(module)]
    return {
        "format_version": 1,
        "coordinate_units": "dword offsets within each function; original source lines/columns where saved",
        "debug_info": module.debug_info,
        "scope_marker_options": {"0": "object_uninitialized_or_destroyed", "1": "object_initialized",
                                 "2": "block_begin", "3": "block_end", "4": "variable_declared"},
        "summary": {
            "function_bodies": len(functions),
            "functions_with_saved_sections": sum(bool(f["saved_source_section"]) for f in functions),
            "saved_parameter_names": sum(len(f["saved_parameter_names"]) for f in functions),
            "saved_local_names": sum(bool(v["saved_name"]) for f in functions for v in f["locals"]),
            "source_line_mappings": sum(len(f["source_line_mappings"]) for f in functions),
        },
        "functions": functions,
        "saved_imports": [{"module": imported.module, "signature": imported.signature.signature()}
                          for imported in module.imported_functions],
        "global_declaration_order": [{
            "index": index, "name": glob.name, "namespace": glob.namespace_, "type": glob.type.format(),
            "initializer_signature": glob.init_func.signature() if glob.init_func else None,
            "saved_source_section": glob.init_func.script_section or None
                if glob.init_func and glob.init_func.has_debug_info else None,
            "saved_declaration": source_location(glob.init_func.declared_at)
                if glob.init_func and glob.init_func.has_debug_info else None,
        } for index, glob in enumerate(module.globals)],
        "not_established": ["original comments and formatting", "original include directives",
                            "names stripped from bytecode", "complete behavioral equivalence"],
    }
