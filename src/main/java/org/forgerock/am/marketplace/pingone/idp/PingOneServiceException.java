package org.forgerock.am.marketplace.pingone.idp;

/**
 * Clear Exception.
 */
public class PingOneServiceException extends Exception {

    /**
     * Exception constructor with error message.
     *
     * @param message The error message.
     */
    public PingOneServiceException(String message) {
        super(message);
    }
}