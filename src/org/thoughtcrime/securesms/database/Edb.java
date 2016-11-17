package org.thoughtcrime.securesms.database;

import android.content.Context;
import android.os.Environment;
import android.util.Log;

import org.thoughtcrime.securesms.crypto.MasterSecret;
import org.thoughtcrime.securesms.database.model.SmsMessageRecord;

import java.io.File;
import java.io.IOException;

/**
 * Created by zheguang on 11/16/16.
 */

public class Edb {

    public static void setupEdb(Context context, MasterSecret masterSecret) {
        Log.i("Edb", "setupEdb");
    }
}
