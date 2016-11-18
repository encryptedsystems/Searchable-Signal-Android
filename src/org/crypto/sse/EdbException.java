package org.crypto.sse;

/**
 * Created by zheguang on 11/17/16.
 */

public class EdbException extends Exception {
    public EdbException() {
    }

    public EdbException(String detailMessage) {
        super(detailMessage);
    }

    public EdbException(Throwable throwable) {
        super(throwable);
    }

    public EdbException(String detailMessage, Throwable throwable) {
        super(detailMessage, throwable);
    }
}
