package parity.adminconsole.backend;

/**
 * A backend's error answer ({@code error: {code, message, rule?}}). {@code message} is for people and
 * may name the backend's view of the request (another tenant, even); the console never passes it on
 * (multi-tenant rule 6).
 */
public record BackendError(String code, String message, String rule) {}
