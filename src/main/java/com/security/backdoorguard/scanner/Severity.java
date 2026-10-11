package com.security.backdoorguard.scanner;

import java.util.Locale;

public enum Severity {
    CLEAN, LOW, MEDIUM, HIGH, CRITICAL;

    public String key() {
        return "severity." + name().toLowerCase(Locale.ROOT);
    }
}
