package tech.humifortis.keycloak.caep;

public class CaepValidationException extends RuntimeException {
    private final int statusCode;

    public CaepValidationException(int statusCode, String message) {
        super(message);
        this.statusCode = statusCode;
    }

    public int getStatusCode() {
        return statusCode;
    }
}
