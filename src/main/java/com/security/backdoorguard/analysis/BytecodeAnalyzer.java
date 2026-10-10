package com.security.backdoorguard.analysis;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Defensive, dependency-free JVM class-file parser. Extracts actual bytecode-referenced
 * members and ldc strings. This is static analysis, not a proof of runtime behavior.
 */
public final class BytecodeAnalyzer {
    private BytecodeAnalyzer() {}

    public record MemberRef(String owner, String name, String descriptor, boolean method) {
        public String normalized() { return owner + "." + name + descriptor; }
    }
    public record Analysis(boolean valid, int majorVersion, String className, String superName,
                           Set<String> classReferences, Set<MemberRef> memberReferences,
                           Set<String> strings, String error) {
        public String apiReferencesText() {
            StringBuilder b = new StringBuilder();
            if (className != null) b.append(className).append('\n');
            if (superName != null) b.append(superName).append('\n');
            classReferences.forEach(s -> b.append(s).append('\n'));
            memberReferences.forEach(r -> b.append(r.normalized()).append('\n'));
            return b.toString();
        }
        public String searchableText() {
            StringBuilder b = new StringBuilder(apiReferencesText());
            strings.forEach(s -> b.append(s).append('\n'));
            return b.toString();
        }
    }

    private static final class Cp {
        int tag, a, b;
        String text;
    }

    public static Analysis analyze(byte[] bytes) {
        Set<String> classes = new LinkedHashSet<>();
        Set<MemberRef> members = new LinkedHashSet<>();
        Set<String> strings = new LinkedHashSet<>();
        String className = null, superName = null;
        int major = 0;
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(bytes))) {
            if (in.readInt() != 0xCAFEBABE) return invalid(classes, members, strings, "bad magic");
            in.readUnsignedShort();
            major = in.readUnsignedShort();
            int cpCount = in.readUnsignedShort();
            if (cpCount < 1 || cpCount > 65535) return invalid(classes, members, strings, "bad constant pool count");
            Cp[] cp = new Cp[cpCount];
            for (int i = 1; i < cpCount; i++) {
                Cp e = new Cp(); e.tag = in.readUnsignedByte(); cp[i] = e;
                switch (e.tag) {
                    case 1 -> {
                        // CONSTANT_Utf8_info uses JVM modified UTF-8; DataInputStream.readUTF
                        // implements the class-file length-prefix/encoding rules directly.
                        e.text = in.readUTF();
                    }
                    case 3, 4 -> in.readInt();
                    case 5, 6 -> {
                        in.readLong();
                        if (i + 1 >= cpCount) throw new IOException("long/double constant has no reserved slot");
                        i++;
                    }
                    case 7, 8, 16, 19, 20 -> e.a = in.readUnsignedShort();
                    case 9, 10, 11, 12, 17, 18 -> { e.a = in.readUnsignedShort(); e.b = in.readUnsignedShort(); }
                    case 15 -> { e.a = in.readUnsignedByte(); e.b = in.readUnsignedShort(); }
                    default -> { return invalid(classes, members, strings, "unknown constant-pool tag " + e.tag); }
                }
            }
            in.readUnsignedShort();
            int thisClass = in.readUnsignedShort();
            int superClass = in.readUnsignedShort();
            className = className(cp, thisClass);
            superName = className(cp, superClass);
            if (className != null) classes.add(className);
            if (superName != null) classes.add(superName);
            int ifaceCount = in.readUnsignedShort();
            for (int i = 0; i < ifaceCount; i++) addClass(cp, in.readUnsignedShort(), classes);
            Set<Integer> bootstrapIndices = new LinkedHashSet<>();
            skipMembers(in, cp, false, classes, members, strings, bootstrapIndices);
            skipMembers(in, cp, true, classes, members, strings, bootstrapIndices);
            int classAttributes = in.readUnsignedShort();
            for (int a = 0; a < classAttributes; a++) {
                String attrName = utf(cp, in.readUnsignedShort());
                if (attrName == null) throw new IOException("invalid class attribute name index");
                long attrLength = Integer.toUnsignedLong(in.readInt());
                if (attrLength > in.available()) throw new IOException("truncated class attribute " + attrName);
                byte[] attr = in.readNBytes((int) attrLength);
                if ("BootstrapMethods".equals(attrName)) parseBootstrapMethods(attr, cp, bootstrapIndices, classes, members, strings);
            }
            if (className == null) throw new IOException("invalid this_class reference");
            if (in.available() != 0) throw new IOException("trailing bytes after class attributes");
            // ConstantValue fields can store strings that are not loaded by an LDC opcode.
            // Do not count every unused member reference as behavior; executable references are extracted from Code.
            for (int i = 1; i < cp.length; i++) {
                Cp e = cp[i]; if (e != null && e.tag == 8) addUtf(cp, e.a, strings);
            }
            return new Analysis(true, major, className, superName, Set.copyOf(classes), Set.copyOf(members), Set.copyOf(strings), "");
        } catch (IOException | RuntimeException ex) {
            return new Analysis(false, major, className, superName, Set.copyOf(classes), Set.copyOf(members), Set.copyOf(strings),
                    ex.getMessage() == null ? ex.getClass().getSimpleName() : ex.getMessage());
        }
    }

    private static Analysis invalid(Set<String> c, Set<MemberRef> m, Set<String> s, String error) {
        return new Analysis(false, 0, null, null, Set.copyOf(c), Set.copyOf(m), Set.copyOf(s), error);
    }

    private static void skipMembers(DataInputStream in, Cp[] cp, boolean methods, Set<String> classes,
                                    Set<MemberRef> refs, Set<String> strings, Set<Integer> bootstrapIndices) throws IOException {
        int count = in.readUnsignedShort();
        for (int i = 0; i < count; i++) {
            in.readUnsignedShort(); // access flags
            in.readUnsignedShort(); // name
            in.readUnsignedShort(); // descriptor
            int attributes = in.readUnsignedShort();
            for (int a = 0; a < attributes; a++) {
                String attrName = utf(cp, in.readUnsignedShort());
                if (attrName == null) throw new IOException("invalid member attribute name index");
                long attrLength = Integer.toUnsignedLong(in.readInt());
                if (attrLength > in.available()) throw new IOException("truncated attribute " + attrName);
                byte[] attr = in.readNBytes((int) attrLength);
                if (methods && "Code".equals(attrName)) parseCode(attr, cp, classes, refs, strings, bootstrapIndices);
            }
        }
    }

    private static void parseCode(byte[] data, Cp[] cp, Set<String> classes, Set<MemberRef> refs,
                                  Set<String> strings, Set<Integer> bootstrapIndices) throws IOException {
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(data))) {
            in.readUnsignedShort(); in.readUnsignedShort();
            long len = Integer.toUnsignedLong(in.readInt());
            if (len == 0 || len > 65535 || len > in.available()) throw new IOException("invalid code length");
            byte[] code = in.readNBytes((int) len);
            walkInstructions(code, cp, classes, refs, strings, bootstrapIndices);
            int exceptionCount = in.readUnsignedShort();
            for (int i = 0; i < exceptionCount; i++) {
                int startPc = in.readUnsignedShort();
                int endPc = in.readUnsignedShort();
                int handlerPc = in.readUnsignedShort();
                int catchType = in.readUnsignedShort();
                if (startPc >= endPc || endPc > code.length || handlerPc >= code.length
                        || (catchType != 0 && (catchType >= cp.length || cp[catchType] == null || cp[catchType].tag != 7))) {
                    throw new IOException("invalid exception table entry");
                }
            }
            int nestedAttributes = in.readUnsignedShort();
            for (int i = 0; i < nestedAttributes; i++) {
                String attributeName = utf(cp, in.readUnsignedShort());
                if (attributeName == null) throw new IOException("invalid Code attribute name index");
                long attributeLength = Integer.toUnsignedLong(in.readInt());
                if (attributeLength > in.available()) throw new IOException("truncated Code attribute " + attributeName);
                in.skipNBytes(attributeLength);
            }
            if (in.available() != 0) throw new IOException("trailing bytes in Code attribute");
        }
    }

    private static void walkInstructions(byte[] code, Cp[] cp, Set<String> classes, Set<MemberRef> refs,
                                         Set<String> strings, Set<Integer> bootstrapIndices) throws IOException {
        int pc = 0;
        while (pc < code.length) {
            int start = pc, op = code[pc++] & 0xff;
            switch (op) {
                case 0x12 -> addConstant(cp, code[pc++] & 0xff, classes, refs, strings, bootstrapIndices);
                case 0x13, 0x14 -> { addConstant(cp, u2(code, pc), classes, refs, strings, bootstrapIndices); pc += 2; }
                case 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8 -> { addReference(cp, u2(code, pc), classes, refs); pc += 2; }
                case 0xb9 -> { addReference(cp, u2(code, pc), classes, refs); pc += 4; }
                case 0xba -> { int index = u2(code, pc); addBootstrapIndex(cp, index, bootstrapIndices); pc += 4; }
                case 0xbb, 0xbd, 0xc0, 0xc1 -> { addClass(cp, u2(code, pc), classes); pc += 2; }
                case 0xc5 -> { addClass(cp, u2(code, pc), classes); pc += 3; }
                case 0xaa -> { // tableswitch; padding is relative to start of opcode
                    while ((pc & 3) != 0) pc++;
                    require(code, pc, 12);
                    int low = i4(code, pc + 4), high = i4(code, pc + 8);
                    long count = (long) high - low + 1;
                    if (count < 0 || count > code.length / 4L) throw new IOException("invalid tableswitch");
                    pc += 12 + (int) count * 4;
                }
                case 0xab -> { // lookupswitch
                    while ((pc & 3) != 0) pc++;
                    require(code, pc, 8);
                    int pairs = i4(code, pc + 4);
                    if (pairs < 0 || pairs > code.length / 8) throw new IOException("invalid lookupswitch");
                    pc += 8 + pairs * 8;
                }
                case 0xc4 -> {
                    require(code, pc, 1); int next = code[pc] & 0xff;
                    pc += (next == 0x84 ? 5 : 3);
                }
                default -> pc += operandLength(op);
            }
            if (pc <= start || pc > code.length) throw new IOException("invalid bytecode instruction at " + start);
        }
    }

    private static int operandLength(int op) throws IOException {
        if ((op >= 0x99 && op <= 0xa8) || op == 0xc6 || op == 0xc7) return 2;
        if (op == 0xc8 || op == 0xc9) return 4;
        if (op == 0x10 || op == 0x15 || op == 0x16 || op == 0x17 || op == 0x18 || op == 0x19
                || (op >= 0x36 && op <= 0x3a) || op == 0xa9 || op == 0xbc) return 1;
        if (op == 0x11 || op == 0x84 || (op >= 0x99 && op <= 0xa7)) return 2;
        if (op >= 0x00 && op <= 0xc9) return 0;
        throw new IOException("unknown bytecode opcode " + op);
    }

    private static void addConstant(Cp[] cp, int idx, Set<String> classes, Set<MemberRef> refs,
                                    Set<String> strings, Set<Integer> bootstrapIndices) {
        if (idx <= 0 || idx >= cp.length || cp[idx] == null) return;
        Cp e = cp[idx];
        if (e.tag == 8) addUtf(cp, e.a, strings);
        else if (e.tag == 7) addClass(cp, idx, classes);
        else if (e.tag == 15) addReference(cp, e.b, classes, refs);
        else if (e.tag == 17) addBootstrapIndex(cp, idx, bootstrapIndices);
    }

    private static void addBootstrapIndex(Cp[] cp, int idx, Set<Integer> bootstrapIndices) {
        if (idx <= 0 || idx >= cp.length || cp[idx] == null) return;
        Cp e = cp[idx];
        if (e.tag == 17 || e.tag == 18) bootstrapIndices.add(e.a);
    }

    private static void parseBootstrapMethods(byte[] data, Cp[] cp, Set<Integer> needed,
                                              Set<String> classes, Set<MemberRef> refs, Set<String> strings) throws IOException {
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(data))) {
            int count = in.readUnsignedShort();
            for (int i = 0; i < count; i++) {
                int methodHandle = in.readUnsignedShort();
                int args = in.readUnsignedShort();
                boolean inspect = needed.contains(i);
                if (inspect) addHandle(cp, methodHandle, classes, refs);
                for (int j = 0; j < args; j++) {
                    int arg = in.readUnsignedShort();
                    if (inspect) {
                        if (arg > 0 && arg < cp.length && cp[arg] != null && cp[arg].tag == 15) addHandle(cp, arg, classes, refs);
                        else addConstant(cp, arg, classes, refs, strings, needed);
                    }
                }
            }
            if (in.available() != 0) throw new IOException("trailing bytes in BootstrapMethods attribute");
        }
    }

    private static void addHandle(Cp[] cp, int idx, Set<String> classes, Set<MemberRef> refs) {
        if (idx <= 0 || idx >= cp.length || cp[idx] == null || cp[idx].tag != 15) return;
        addReference(cp, cp[idx].b, classes, refs);
    }

    private static void addReference(Cp[] cp, int idx, Set<String> classes, Set<MemberRef> refs) {
        MemberRef r = memberRef(cp, idx);
        if (r != null) { refs.add(r); classes.add(r.owner()); }
    }
    private static MemberRef memberRef(Cp[] cp, int idx) {
        if (idx <= 0 || idx >= cp.length || cp[idx] == null) return null;
        Cp e = cp[idx]; if (e.tag != 9 && e.tag != 10 && e.tag != 11) return null;
        String owner = className(cp, e.a);
        if (e.b <= 0 || e.b >= cp.length || cp[e.b] == null || cp[e.b].tag != 12) return null;
        Cp nt = cp[e.b]; String name = utf(cp, nt.a), desc = utf(cp, nt.b);
        if (owner == null || name == null || desc == null) return null;
        return new MemberRef(owner, name, desc, e.tag == 10 || e.tag == 11);
    }
    private static void addClass(Cp[] cp, int idx, Set<String> classes) {
        String name = className(cp, idx); if (name != null) classes.add(name);
    }
    private static String className(Cp[] cp, int idx) {
        if (idx <= 0 || idx >= cp.length || cp[idx] == null || cp[idx].tag != 7) return null;
        String s = utf(cp, cp[idx].a); return s == null ? null : s;
    }
    private static void addUtf(Cp[] cp, int idx, Set<String> out) {
        String s = utf(cp, idx); if (s != null && !s.isEmpty()) out.add(s);
    }
    private static String utf(Cp[] cp, int idx) {
        return idx > 0 && idx < cp.length && cp[idx] != null && cp[idx].tag == 1 ? cp[idx].text : null;
    }
    private static int u2(byte[] b, int p) throws IOException { require(b, p, 2); return ((b[p] & 0xff) << 8) | (b[p + 1] & 0xff); }
    private static int i4(byte[] b, int p) throws IOException { require(b, p, 4); return (b[p] << 24) | ((b[p + 1] & 0xff) << 16) | ((b[p + 2] & 0xff) << 8) | (b[p + 3] & 0xff); }
    private static void require(byte[] b, int p, int n) throws IOException { if (p < 0 || n < 0 || p + n > b.length) throw new IOException("truncated bytecode"); }
}
