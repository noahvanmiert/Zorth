const std = @import("std");

const print = std.debug.print;
const exit = std.process.exit;

const Globals = enum(i32) {
    MemoryCapacity = 640000,
};

const OpType = enum {
    Push,
    Plus,
    Minus,
    Eq,
    Dup,
    Dup2,
    Drop,
    Swap,
    Over,
    Gt,
    St,
    Dump,
    If,
    Else,
    While,
    Do,
    End,
    Mem,
    Load,   // 1 byte 
    Store,   // 1 byte
    Syscall1,
    Syscall3,
    Shr,
    Shl,
    Bor,
    Band
};


const Location = struct {
    line: i32,
    col: i32,
    filepath: []const u8,

    pub fn init(line: i32, col: i32, filepath: []const u8) Location {
        return Location {
            .line = line,
            .col = col,
            .filepath = filepath
        };
    }
};


const Op = struct {
    type: OpType,
    arg: ?i32,
    loc: Location,

    pub fn init(op_type: OpType) Op {
        return Op {
            .type = op_type,
            .arg = null,
            .loc = Location.init(0, 0, "")
        };
    }

    pub fn initWithArg(op_type: OpType, arg: i32) Op {
        return Op {
            .type = op_type,
            .arg = arg,
            .loc = Location.init(0, 0, "")
        };
    }
};
   

fn compile_program(program: std.ArrayList(Op), outFilepath: []const u8) !void { 
    const file = try std.fs.cwd().createFile(
        outFilepath,
        .{ .read = true },
    );
    defer file.close();

    _ = try file.write("BITS 64\n");
    _ = try file.write("segment .text\n");
    try file.writer().print("print:\n", .{});
    try file.writer().print("    mov     r9, -3689348814741910323\n", .{});
    try file.writer().print("    sub     rsp, 40\n", .{});
    try file.writer().print("    mov     BYTE [rsp+31], 10\n", .{});
    try file.writer().print("    lea     rcx, [rsp+30]\n", .{});
    try file.writer().print(".L2:\n", .{});
    try file.writer().print("    mov     rax, rdi\n", .{});
    try file.writer().print("    lea     r8, [rsp+32]\n", .{});
    try file.writer().print("    mul     r9\n", .{});
    try file.writer().print("    mov     rax, rdi\n", .{});
    try file.writer().print("    sub     r8, rcx\n", .{});
    try file.writer().print("    shr     rdx, 3\n", .{});
    try file.writer().print("    lea     rsi, [rdx+rdx*4]\n", .{});
    try file.writer().print("    add     rsi, rsi\n", .{});
    try file.writer().print("    sub     rax, rsi\n", .{});
    try file.writer().print("    add     eax, 48\n", .{});
    try file.writer().print("    mov     BYTE [rcx], al\n", .{});
    try file.writer().print("    mov     rax, rdi\n", .{});
    try file.writer().print("    mov     rdi, rdx\n", .{});
    try file.writer().print("    mov     rdx, rcx\n", .{});
    try file.writer().print("    sub     rcx, 1\n", .{});
    try file.writer().print("    cmp     rax, 9\n", .{});
    try file.writer().print("    ja      .L2\n", .{});
    try file.writer().print("    lea     rax, [rsp+32]\n", .{});
    try file.writer().print("    mov     edi, 1\n", .{});
    try file.writer().print("    sub     rdx, rax\n", .{});
    try file.writer().print("    xor     eax, eax\n", .{});
    try file.writer().print("    lea     rsi, [rsp+32+rdx]\n", .{});
    try file.writer().print("    mov     rdx, r8\n", .{});
    try file.writer().print("    mov     rax, 1\n", .{});
    try file.writer().print("    syscall\n", .{});
    try file.writer().print("    add     rsp, 40\n", .{});
    try file.writer().print("    ret\n", .{});
    _ = try file.write("global _start\n");
    _ = try file.write("_start:\n");

    var ip: usize = 0;
    while (ip < program.items.len) {
        const op = program.items[ip];
        
        try file.writer().print("addr_{}:\n", .{ip});
        switch (op.type) {
            OpType.Push => {
                try file.writer().print("    ;; -- push {?} --\n", .{op.arg});
                try file.writer().print("    push {?}\n", .{op.arg});
            },

            OpType.Plus => {
                try file.writer().print("    ;; -- plus --\n", .{});
                try file.writer().print("    pop rax\n", .{});
                try file.writer().print("    pop rbx\n", .{});
                try file.writer().print("    add rax, rbx\n", .{});
                try file.writer().print("    push rax\n", .{});
            },

            OpType.Minus => {
                try file.writer().print("    ;; -- minus --\n", .{});
                try file.writer().print("    pop rax\n", .{});
                try file.writer().print("    pop rbx\n", .{});
                try file.writer().print("    sub rbx, rax\n", .{});
                try file.writer().print("    push rbx\n", .{});
            },

            OpType.Eq => {
                try file.writer().print("    ;; -- eq --\n", .{});
                try file.writer().print("    mov rcx, 0\n", .{});
                try file.writer().print("    mov rdx, 1\n", .{});
                try file.writer().print("    pop rax\n", .{});
                try file.writer().print("    pop rbx\n", .{});
                try file.writer().print("    cmp rax, rbx\n", .{});
                try file.writer().print("    cmove rcx, rdx\n", .{});
                try file.writer().print("    push rcx\n", .{});
            },

            OpType.Gt => {
                try file.writer().print("    ;; -- gt --\n", .{});
                try file.writer().print("    mov rcx, 0\n", .{});
                try file.writer().print("    mov rdx, 1\n", .{});
                try file.writer().print("    pop rbx\n", .{});
                try file.writer().print("    pop rax\n", .{});
                try file.writer().print("    cmp rax, rbx\n", .{});
                try file.writer().print("    cmovg rcx, rdx\n", .{});
                try file.writer().print("    push rcx\n", .{});
                
            },

            OpType.St => {
                try file.writer().print("    ;; -- st --\n", .{});
                try file.writer().print("    mov rcx, 0\n", .{});
                try file.writer().print("    mov rdx, 1\n", .{});
                try file.writer().print("    pop rbx\n", .{});
                try file.writer().print("    pop rax\n", .{});
                try file.writer().print("    cmp rax, rbx\n", .{});
                try file.writer().print("    cmovl rcx, rdx\n", .{});
                try file.writer().print("    push rcx\n", .{});
                
            },

            OpType.Dup => {
                try file.writer().print("    ;; -- dup --\n", .{});
                try file.writer().print("    pop rax\n", .{});
                try file.writer().print("    push rax\n", .{});
                try file.writer().print("    push rax\n", .{});
            },

            OpType.Dup2 => {
                try file.writer().print("    ;; -- 2dup --\n", .{});
                try file.writer().print("    pop rbx\n", .{});
                try file.writer().print("    pop rax\n", .{});
                try file.writer().print("    push rax\n", .{});
                try file.writer().print("    push rbx\n", .{});
                try file.writer().print("    push rax\n", .{});
                try file.writer().print("    push rbx\n", .{});
            },

            OpType.Drop => {
                try file.writer().print("    ;; -- drop --\n", .{});
                try file.writer().print("    pop rax\n", .{});
            },

            OpType.Swap => {
                try file.writer().print("    ;; -- swap --\n", .{});
                try file.writer().print("    pop rax\n", .{});
                try file.writer().print("    pop rbx\n", .{});
                try file.writer().print("    push rax\n", .{});
                try file.writer().print("    push rbx\n", .{});
            },

            OpType.Over => {
                try file.writer().print("    ;; -- over --\n", .{});
                try file.writer().print("    pop rax\n", .{});
                try file.writer().print("    pop rbx\n", .{});
                try file.writer().print("    push rbx\n", .{});
                try file.writer().print("    push rax\n", .{});
                try file.writer().print("    push rbx\n", .{});
            },

            OpType.If => {
                try file.writer().print("    ;; -- if --\n", .{});
                try file.writer().print("    pop rax\n", .{});
                try file.writer().print("    test rax, rax\n", .{});

                if (op.arg == null) {
                    print("{s}:{d}:{d}: `if` instruction does not have a reference to the end of its block\n", .{op.loc.filepath, op.loc.line, op.loc.col});
                    exit(1);
                }

                try file.writer().print("    jz addr_{?}\n", .{op.arg});
            },

            OpType.Else => {
                if (op.arg == null) {
                    print("{s}:{d}:{d}: `else` instruction does not have a reference to the end of its block\n", .{op.loc.filepath, op.loc.line, op.loc.col});
                    exit(1);
                }
                
                try file.writer().print("    ;; -- else --\n", .{});
                try file.writer().print("    jmp addr_{?}\n", .{op.arg});
            },

            OpType.While => {
                try file.writer().print("    ;; -- while --\n", .{});
            },

            OpType.Do => {
                try file.writer().print("    ;; -- do --\n", .{});
                try file.writer().print("    pop rax\n", .{});
                try file.writer().print("    test rax, rax\n", .{});

                if (op.arg == null) {
                    print("{s}:{d}:{d}: `if` instruction does not have a reference to the end of its block\n", .{op.loc.filepath, op.loc.line, op.loc.col});
                    exit(1);
                }
                
                try file.writer().print("    jz addr_{?}\n", .{op.arg.?});
            },

            OpType.End => {
                if (op.arg == null) {
                    print("{s}:{d}:{d}: `end` instruction does not have a reference to the next instruction to jump to\n", .{op.loc.filepath, op.loc.line, op.loc.col});
                    exit(1);
                }

                try file.writer().print("    ;; -- end --\n", .{});
                if (ip + 1 != op.arg.?) {
                    try file.writer().print("    jmp addr_{?}\n", .{op.arg});
                }
            },

            OpType.Mem => {
                try file.writer().print("    ;; -- mem --\n", .{});
                try file.writer().print("    push mem\n", .{});
             },

            OpType.Dump => {
                try file.writer().print("    ;; -- dump --\n", .{});
                try file.writer().print("    pop rdi\n", .{});
                try file.writer().print("    call print\n", .{});
            },

            OpType.Load => {
                try file.writer().print("    ;; -- load8 --\n", .{});
                try file.writer().print("    pop rax\n", .{});
                try file.writer().print("    xor rbx, rbx\n", .{});
                try file.writer().print("    mov bl, [rax]\n", .{});
                try file.writer().print("    push rbx\n", .{});
            },

            OpType.Store => {
                try file.writer().print("    ;; -- store8 --\n", .{});
                try file.writer().print("    pop rbx\n", .{});
                try file.writer().print("    pop rax\n", .{});
                try file.writer().print("    mov [rax], bl\n", .{});
            },

            OpType.Syscall1 => {
                try file.writer().print("    ;; -- syscall1 --\n", .{});
                try file.writer().print("    pop rax\n", .{});
                try file.writer().print("    pop rdi\n", .{});
                try file.writer().print("    syscall\n", .{});
            },

            OpType.Syscall3 => {
                try file.writer().print("    ;; -- syscall3 --\n", .{});
                try file.writer().print("    pop rax\n", .{});
                try file.writer().print("    pop rdi\n", .{});
                try file.writer().print("    pop rsi\n", .{});
                try file.writer().print("    pop rdx\n", .{});
                try file.writer().print("    syscall\n", .{});
                
            },

            OpType.Shr => {
                try file.writer().print("    ;; -- shr --\n", .{});
                try file.writer().print("    pop rcx\n", .{});
                try file.writer().print("    pop rbx\n", .{});
                try file.writer().print("    shr rbx, cl\n", .{});
                try file.writer().print("    push rbx\n", .{});
            },

            OpType.Shl => {
                try file.writer().print("    ;; -- shl --\n", .{});
                try file.writer().print("    pop rcx\n", .{});
                try file.writer().print("    pop rbx\n", .{});
                try file.writer().print("    shl rbx, cl\n", .{});
                try file.writer().print("    push rbx\n", .{});
            },

            OpType.Bor => {
                try file.writer().print("    ;; -- bor --\n", .{});
                try file.writer().print("    pop rax\n", .{});
                try file.writer().print("    pop rbx\n", .{});
                try file.writer().print("    or rbx, rax\n", .{});
                try file.writer().print("    push rbx\n", .{});
            },

            OpType.Band => {
                try file.writer().print("    ;; -- band --\n", .{});
                try file.writer().print("    pop rax\n", .{});
                try file.writer().print("    pop rbx\n", .{});
                try file.writer().print("    and rbx, rax\n", .{});
                try file.writer().print("    push rbx\n", .{});
            },

        }

        ip += 1;
    }
    
    try file.writer().print("addr_{}:\n", .{program.items.len});
    _ = try file.write("    ;; exit with non-zero exit code\n");
    _ = try file.write("    mov rax, 60\n");
    _ = try file.write("    mov rdi, 0\n");
    _ = try file.write("    syscall\n");

    _ = try file.write("segment .bss\n");
    try file.writer().print("mem: resb {d}\n", .{@intFromEnum(Globals.MemoryCapacity)});
}


fn crossreferenceProgram(program: *std.ArrayList(Op)) !void {
    var stack = std.ArrayList(usize).init(std.heap.page_allocator);
    defer stack.deinit();
    
    var ip: usize = 0;
    while (ip < program.items.len) {
        const op = program.items[ip];

        if (op.type == OpType.If) {
            try stack.append(ip);
        } else if (op.type == OpType.Else) {
            if (stack.items.len < 1) {
                print("{s}:{d}:{d}: `else` can only be used with if-blocks\n", .{op.loc.filepath, op.loc.line, op.loc.col});
                exit(1);
            }

            const if_ip = stack.pop();

            if (program.items[if_ip].type != OpType.If) {
                print("{s}:{d}:{d}: `else` can only be used with `if` blocks\n", .{op.loc.filepath, op.loc.line, op.loc.col});
                exit(1);
            }

            program.items[if_ip].arg = @intCast(ip + 1);
            try stack.append(ip);
        } else if (op.type == OpType.End) {
            if (stack.items.len < 1) {
                print("{s}:{d}:{d}: `else` can only be used with `if` blocks\n", .{op.loc.filepath, op.loc.line, op.loc.col});
                exit(1);
            }

            const block_ip = stack.pop();
            
            if (program.items[block_ip].type == OpType.If or program.items[block_ip].type == OpType.Else)  {
                program.items[block_ip].arg = @intCast(ip);
                program.items[ip].arg = @intCast(ip + 1);
            } else if (program.items[block_ip].type == OpType.Do) {
                 if (program.items[block_ip].arg == null) {
                     std.debug.assert(false);
                }
                
                program.items[ip].arg = program.items[block_ip].arg;
                program.items[block_ip].arg = @intCast(ip + 1);
            } else {
                print("{s}:{d}:{d}: `end` can only close `if`, `else` and `while` blocks for now\n", .{op.loc.filepath, op.loc.line, op.loc.col});
                exit(1);
            }
        } else if (op.type == OpType.While) {
            try stack.append(ip);
        } else if (op.type == OpType.Do) {
            if (stack.items.len < 1) {
                print("{s}:{d}:{d}: `do` can only be used with `while` blocks\n", .{op.loc.filepath, op.loc.line, op.loc.col});
                exit(1);
            }

            const while_ip = stack.pop();
            program.items[ip].arg = @intCast(while_ip);
            try stack.append(ip);
        }
    
        ip += 1;
    }
            
}


fn mapInsert(key: []const u8, value: OpType, map: *std.StringHashMap(OpType)) void {
    map.put(key, value) catch |err| {
        print("error occured while trying to put value into map: {?}\n", .{err});
        exit(1);
    };
}


fn parseWordAsOperation(token: []const u8, line: i32, col: i32, filepath: []const u8) Op {
    var map = std.StringHashMap(OpType).init(std.heap.page_allocator);
    defer map.deinit();

    mapInsert("+", OpType.Plus, &map);
    mapInsert("-", OpType.Minus, &map);
    mapInsert("=", OpType.Eq, &map);
    mapInsert("dump", OpType.Dump, &map);
    mapInsert(">", OpType.Gt, &map);
    mapInsert("<", OpType.St, &map);
    mapInsert("dup", OpType.Dup, &map);
    mapInsert("2dup", OpType.Dup2, &map);
    mapInsert("drop", OpType.Drop, &map);
    mapInsert("swap", OpType.Swap, &map);
    mapInsert("over", OpType.Over, &map);
    mapInsert("if", OpType.If, &map);
    mapInsert("else", OpType.Else, &map);
    mapInsert("while", OpType.While, &map);
    mapInsert("do", OpType.Do, &map);
    mapInsert("end", OpType.End, &map);
    mapInsert("mem", OpType.Mem, &map);
    mapInsert("load8", OpType.Load, &map);
    mapInsert("store8", OpType.Store, &map);
    mapInsert("syscall1", OpType.Syscall1, &map);
    mapInsert("syscall3", OpType.Syscall3, &map);
    mapInsert("shl", OpType.Shl, &map);
    mapInsert("shr", OpType.Shr, &map);
    mapInsert("bor", OpType.Bor, &map);
    mapInsert("band", OpType.Band, &map);

    if (map.get(token)) |op_type| {
        return Op.init(op_type);
    }

    const result = std.fmt.parseInt(i32, token, 10) catch |err| {
        if (err == std.fmt.ParseIntError.InvalidCharacter) {
            print("{s}:{d}:{d}: Unkown word: {s}\n", .{filepath, line, col, token});    
        } else {
            print("{s}:{d}:{d}: {?}", .{filepath, line, col, err});
        }

        std.process.exit(1);
    };

    return Op.initWithArg(OpType.Push, result);
}



fn loadProgramFromFile(allocator: *std.mem.Allocator, path: []const u8) !std.ArrayList(Op) {
    var file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    var tokens = std.ArrayList(Op).init(allocator.*);
    var reader = std.io.bufferedReader(file.reader());
    var line_number: i32 = 1;

    while (true) {
        const line = try reader.reader().readUntilDelimiterOrEofAlloc(allocator.*, '\n', 255);
        
        // if EOF is reached, stop
        if (line == null) break;
        
        const line_start = line.?[0..].ptr; // Pointer to the start of the line

        var tokenizer = std.mem.tokenize(u8, line.?, " \n\t\r");
        while (tokenizer.next()) |token| {
            if (token.len >= 2 and std.mem.eql(u8, token[0..2], "//")) {
                break;
            }

            // Pointer to the start of the current token 
            const token_start = token.ptr;

            // We get the column by subtracting the start of the token minus the start of the line + 1 (because the 0th col should be 1)
            const col = @intFromPtr(token_start) - @intFromPtr(line_start) + 1;

            const trimmed_token = std.mem.trimLeft(u8, token, " \n\t\r");
            var operation = parseWordAsOperation(trimmed_token, line_number, @intCast(col), path);
            
            operation.loc = Location.init(line_number, @intCast(col), path);

            try tokens.append(operation);
        }
        
        line_number += 1;
        allocator.free(line.?);
    }

    return tokens;
}


fn runCommand(command: []const []const u8) !void {
    const allocator = std.heap.page_allocator;
    var child = std.process.Child.init(command, allocator);

    try child.spawn();
    const exit_code = try child.wait();

    if (exit_code.Exited != 0) {
        print("Subprocess failed ({s}) with exit code {?}\n", .{command[0], exit_code});
    }
}   


fn usage() void {
    print("Usage: zorth <SUBCOMMAND> [ARGS]\n", .{});
    print("SUBCOMMANDS:\n", .{});
    print("    com <file>    Compile the program\n", .{});
}


pub fn main() !void {
    var allocator = std.heap.page_allocator;

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var argv = args;
        
    if (args.len < 2) {
        print("ERROR: no subcommand provided!\n", .{});
        usage();
        std.process.exit(1);
    }

    argv = argv[1..]; // remove program

    const subcommand = args[1];
    argv = argv[1..]; // remove subcommand
        
    if (std.mem.eql(u8, subcommand, "com")) {
        if (argv.len < 1) {
            usage();
            print("ERROR: no input file is  provided for the compilation\n", .{});
            exit(1);
        }

        var program = try loadProgramFromFile(&allocator, argv[0]);
        defer program.deinit();

        try crossreferenceProgram(&program);
        try compile_program(program, "output.asm");

        try runCommand(&.{"nasm", "-felf64", "output.asm"});
        try runCommand(&.{"ld", "-o", "output", "output.o"});
    } else {
        print("ERROR: unkown subcommand: {s}\n", .{subcommand});
        usage();
        exit(1);
    }
}

