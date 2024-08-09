const std = @import("std");
const print = std.debug.print;

const OpType = enum {
    Push,
    Plus,
    Minus,
    Dump
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
    arg: i32,
    loc: Location,

    pub fn init(op_type: OpType) Op {
        return Op {
            .type = op_type,
            .arg = 0,
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
   

fn simulate_program(program: std.ArrayList(Op)) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};

    var stack = std.ArrayList(i32).init(gpa.allocator());
    defer stack.deinit();

    for (program.items) |op| {
        switch (op.type) {
            OpType.Push => {
                try stack.append(op.arg);
            },

            OpType.Plus => {
                const a = stack.pop();
                const b = stack.pop();
                try stack.append(a + b);
            },

            OpType.Minus => {
                const a = stack.pop();
                const b = stack.pop();
                try stack.append(b - a);
            },

            OpType.Dump => {
                print("{d}\n", .{stack.pop()});
            },
        }
    }
}


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

    for (program.items) |op| {
        switch (op.type) {
            OpType.Push => {
                try file.writer().print("    ;; -- push {d} --\n", .{op.arg});
                try file.writer().print("    push {d}\n", .{op.arg});
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

            OpType.Dump => {
                try file.writer().print("    ;; -- dump --\n", .{});
                try file.writer().print("    pop rdi\n", .{});
                try file.writer().print("    call print\n", .{});
            }
        }
    }

    _ = try file.write("    ;; exit with non-zero exit code\n");
    _ = try file.write("    mov rax, 60\n");
    _ = try file.write("    mov rdi, 0\n");
    _ = try file.write("    syscall\n");
}


fn parseWordAsOperation(token: []const u8, line: i32, col: i32, filepath: []const u8) Op {
    if (std.mem.eql(u8, token, "+")) {
        return Op.init(OpType.Plus);
    } else if (std.mem.eql(u8, token, "-")) {
        return Op.init(OpType.Minus);
    } else if (std.mem.eql(u8, token, ".")) {
        return Op.init(OpType.Dump);
    } 

    const result = std.fmt.parseInt(i32, token, 10) catch |err| {
        if (err == std.fmt.ParseIntError.InvalidCharacter) {
            print("{s}:{d}:{d}: Unkown word: {s}\n", .{filepath, line, col, token});    
        } else {
            print("{s}:{d}:{d}: {}", .{filepath, line, col, err});
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
        print("Subprocess failed ({s}) with exit code {}\n", .{command[0], exit_code});
    }
}   


fn usage() void {
    print("Usage: zorth <SUBCOMMAND> [ARGS]\n", .{});
    print("SUBCOMMANDS:\n", .{});
    print("    sim <file>    Simulate the program\n", .{});
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
        
    if (std.mem.eql(u8, subcommand, "sim")) {
        if (argv.len < 1) {
            usage();
            print("ERROR: no input file is provided for the simulation\n", .{});
            std.process.exit(1);
        }

        const program = try loadProgramFromFile(&allocator, argv[0]);
        defer program.deinit();

        try simulate_program(program);
    } else if (std.mem.eql(u8, subcommand, "com")) {
        if (argv.len < 1) {
            usage();
            print("ERROR: no input file is  provided for the compilation\n", .{});
            std.process.exit(1);
        }

        const program = try loadProgramFromFile(&allocator, argv[0]);
        defer program.deinit();

        try compile_program(program, "output.asm");

        try runCommand(&.{"nasm", "-felf64", "output.asm"});
        try runCommand(&.{"ld", "-o", "output", "output.o"});
    } else {
        print("ERROR: unkown subcommand: {s}\n", .{subcommand});
        usage();
        std.process.exit(1);
    }
}

