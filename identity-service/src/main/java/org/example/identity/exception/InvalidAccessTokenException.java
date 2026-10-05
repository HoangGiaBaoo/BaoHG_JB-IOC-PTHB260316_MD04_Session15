package org.example.identity.exception;

public class InvalidAccessTokenException extends RuntimeException {

    public InvalidAccessTokenException(String message) {
        super(message);
    }
}
