#!/usr/bin/python

import argparse
import clang.cindex
import os.path
import sys

def walk(tu, node, results, func):
    if node.kind == clang.cindex.CursorKind.FUNCTION_DECL:
        func = node.spelling
    elif node.kind == clang.cindex.CursorKind.RETURN_STMT:
        expr_type = next((expr.type for expr in node.get_children()), None)
        if expr_type is None:
            return
        tokens = clang.cindex.TokenGroup.get_tokens(tu, node.extent)
        # "return" itself
        token = next(tokens, None)
        if token is None:
            return
        token = next(tokens, None)
        if token is None:
            return
        # stf_status is expected, but _Bool is found
        if expr_type.spelling == 'stf_status' and \
           token.spelling in ['true', 'false']:
            results.append((node.extent, func))
        # _Bool is expected, but stf_status is found
        elif expr_type.spelling == '_Bool' and \
             token.spelling.startswith('STF_'):
            results.append((node.extent, func))
        return
    for c in node.get_children():
        walk(tu, c, results, func)

parser = argparse.ArgumentParser(description='check return types')
parser.add_argument('--clang-resource-dir', type=str)
args = parser.parse_args()

cdb = clang.cindex.CompilationDatabase.fromDirectory('.')
results = []

for command in cdb.getAllCompileCommands():
    if os.path.dirname(command.filename) != command.directory:
        continue
    os.chdir(command.directory)

    clang_args = []
    arg_iter = iter(command.arguments)
    arg = next(arg_iter)              # skip "cc"
    for arg in arg_iter:
        if arg == '-o':         # skip "-o", "filename"
            arg = next(arg_iter, None)
            if not arg:
                break
            continue
        elif arg in [
                command.filename,
                os.path.relpath(command.filename, command.directory),
        ]: # skip the source filename
            continue
        clang_args.append(arg)
    if args.clang_resource_dir:
        clang_args += ['-resource-dir', args.clang_resource_dir]
    index = clang.cindex.Index.create()
    tu = index.parse(os.path.basename(command.filename), args=clang_args)
    walk(tu, tu.cursor, results, None)

if len(results) > 0:
    for result in results:
        print(f"{result[0].start.file}:{result[0].start.line}:{result[1]}")
    sys.exit(1)
