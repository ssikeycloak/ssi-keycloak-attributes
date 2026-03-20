package kodrat.keycloak.constant;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for SSI reason code classification and utility methods.
 */
class SSIReasonCodeTest {

    @Test
    @DisplayName("Recoverable codes are correctly identified")
    void isRecoverable_trueForRecoverableCodes() {
        assertTrue(SSIReasonCode.isRecoverable(SSIReasonCode.TIMEOUT));
        assertTrue(SSIReasonCode.isRecoverable(SSIReasonCode.INVALID));
        assertTrue(SSIReasonCode.isRecoverable(SSIReasonCode.AGENT_UNREACHABLE));
        assertTrue(SSIReasonCode.isRecoverable(SSIReasonCode.PROOF_REQUEST_FAILED));
    }

    @Test
    @DisplayName("Non-recoverable codes return false for isRecoverable")
    void isRecoverable_falseForNonRecoverableCodes() {
        assertFalse(SSIReasonCode.isRecoverable(SSIReasonCode.SESSION_EXPIRED));
        assertFalse(SSIReasonCode.isRecoverable(SSIReasonCode.INVALID_TAB));
        assertFalse(SSIReasonCode.isRecoverable(SSIReasonCode.INTERNAL_ERROR));
        assertFalse(SSIReasonCode.isRecoverable(SSIReasonCode.UNAUTHORIZED));
        assertFalse(SSIReasonCode.isRecoverable(SSIReasonCode.MISSING_PARAMS));
    }

    @Test
    @DisplayName("Terminal codes are correctly identified")
    void isTerminal_trueForTerminalCodes() {
        assertTrue(SSIReasonCode.isTerminal(SSIReasonCode.SESSION_EXPIRED));
        assertTrue(SSIReasonCode.isTerminal(SSIReasonCode.INVALID_TAB));
        assertTrue(SSIReasonCode.isTerminal(SSIReasonCode.INTERNAL_ERROR));
    }

    @Test
    @DisplayName("Non-terminal codes return false for isTerminal")
    void isTerminal_falseForNonTerminalCodes() {
        assertFalse(SSIReasonCode.isTerminal(SSIReasonCode.TIMEOUT));
        assertFalse(SSIReasonCode.isTerminal(SSIReasonCode.INVALID));
        assertFalse(SSIReasonCode.isTerminal(SSIReasonCode.SUCCESS));
        assertFalse(SSIReasonCode.isTerminal(SSIReasonCode.IN_PROGRESS));
    }

    @Test
    @DisplayName("Null and unknown codes are safely handled")
    void nullAndUnknownCodesSafelyHandled() {
        assertFalse(SSIReasonCode.isRecoverable(null));
        assertFalse(SSIReasonCode.isRecoverable("unknown_code"));
        assertFalse(SSIReasonCode.isTerminal(null));
        assertFalse(SSIReasonCode.isTerminal("unknown_code"));
    }

    @Test
    @DisplayName("Success codes are neither recoverable nor terminal")
    void successCodesAreNeutral() {
        assertFalse(SSIReasonCode.isRecoverable(SSIReasonCode.SUCCESS));
        assertFalse(SSIReasonCode.isTerminal(SSIReasonCode.SUCCESS));
        assertFalse(SSIReasonCode.isRecoverable(SSIReasonCode.RESET_OK));
        assertFalse(SSIReasonCode.isTerminal(SSIReasonCode.RESET_OK));
    }
}
