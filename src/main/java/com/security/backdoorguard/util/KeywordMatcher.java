package com.security.backdoorguard.util;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/** Precompiled word/phrase matcher; avoids recompiling a regex for each player command. */
public final class KeywordMatcher {
    private static final Pattern SPLIT = Pattern.compile("[^a-z0-9]+");
    private final Set<String> tokens = new HashSet<>();
    private final List<String> phraseText = new ArrayList<>();
    private final List<Pattern> phrases = new ArrayList<>();

    public KeywordMatcher(List<String> keywords) {
        if (keywords == null) return;
        for (String keyword : keywords) {
            if (keyword == null || keyword.isBlank()) continue;
            String lower = keyword.trim().toLowerCase(Locale.ROOT);
            if (lower.matches("[a-z0-9]+")) {
                tokens.add(lower);
            } else {
                phraseText.add(lower);
                phrases.add(Pattern.compile("(?<![a-z0-9])" + Pattern.quote(lower) + "(?![a-z0-9])"));
            }
        }
    }

    /** Returns the first matching configured word/phrase, or null when none matches. */
    public String firstMatch(String input) {
        if (input == null || input.isEmpty()) return null;
        String lower = input.toLowerCase(Locale.ROOT);
        for (String token : SPLIT.split(lower)) {
            if (!token.isEmpty() && tokens.contains(token)) return token;
        }
        for (int i = 0; i < phrases.size(); i++) {
            if (phrases.get(i).matcher(lower).find()) return phraseText.get(i);
        }
        return null;
    }

    public int size() {
        return tokens.size() + phrases.size();
    }
}
