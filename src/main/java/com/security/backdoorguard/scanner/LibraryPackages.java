package com.security.backdoorguard.scanner;

import java.util.Set;

/** Recognizes common shaded/vendor packages for conservative score damping, never full exemption. */
final class LibraryPackages {
    private static final String[] PREFIXES = {
            "com/google/", "okhttp3/", "okio/", "kotlin/", "kotlinx/", "org/jetbrains/", "org/apache/",
            "org/slf4j/", "org/yaml/", "org/json/", "com/zaxxer/", "org/sqlite/", "org/mariadb/",
            "com/mysql/", "org/postgresql/", "org/h2/", "io/netty/", "redis/clients/", "com/github/benmanes/",
            "net/kyori/", "javassist/", "org/objectweb/asm/", "com/fasterxml/", "org/bstats/", "com/squareup/",
            "org/bouncycastle/", "io/lettuce/", "com/mongodb/", "org/bson/", "org/mozilla/", "org/codehaus/",
            "groovy/", "org/eclipse/", "org/xerial/", "com/j256/", "net/md_5/", "de/tr7zw/", "co/aikar/",
            "com/sun/jna/", "net/java/dev/jna/", "org/reactivestreams/", "reactor/", "io/projectreactor/",
            "org/checkerframework/", "org/intellij/", "javax/", "jakarta/"
    };
    private static final Set<String> SEGMENTS = Set.of(
            "libs", "lib", "shaded", "shadow", "relocated", "thirdparty", "third_party", "vendor",
            "dependencies", "okhttp3", "okio", "kotlin", "hikari", "zaxxer", "gson", "netty", "slf4j", "bstats"
    );

    private LibraryPackages() {}

    static boolean isLibrary(String internalName) {
        if (internalName == null) return false;
        String name = internalName.replace('.', '/');
        for (String prefix : PREFIXES) if (name.startsWith(prefix)) return true;
        int start = 0;
        while (start < name.length()) {
            int slash = name.indexOf('/', start);
            if (slash < 0) break;
            if (SEGMENTS.contains(name.substring(start, slash))) return true;
            start = slash + 1;
        }
        return false;
    }
}
