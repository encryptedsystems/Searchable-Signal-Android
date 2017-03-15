package org.thoughtcrime.securesms.database;

/**
 * Created by zheguang on 11/17/16.
 */

public class EdbException extends RuntimeException {
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
