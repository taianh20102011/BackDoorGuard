package com.security.backdoorguard.violation;

/**
 * Trong so diem nghi van cho tung loai hanh vi, doc tu config.yml (muc "violation-weights").
 * Tach rieng thanh record de de doc va de chinh sua tu config ma khong dam vao logic.
 */
public record Weights(
        double suspiciousKeyword,
        double unregisteredCommand,
        double injectedCommand,
        double unauthorizedOp,
        double chatTriggeredOp
) {}
