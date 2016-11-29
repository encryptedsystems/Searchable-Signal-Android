package org.thoughtcrime.securesms.database;

import android.os.Parcel;
import android.os.Parcelable;
import android.util.Log;

import org.crypto.sse.EdbException;
import org.crypto.sse.IEX2Lev;
import org.crypto.sse.MMGlobal;
import org.crypto.sse.RH2Lev;
import org.thoughtcrime.securesms.util.Util;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.List;

import javax.crypto.spec.SecretKeySpec;

/**
 * Created by zheguang on 11/27/16.
 */

public class EdbSecret implements Parcelable {
    private static final int KEY_BIT_SIZE = 128;
    public static final int KEY_BYTE_SIZE = KEY_BIT_SIZE / 8;
    public static final int NUM_KEYS = 1;
    private final SecretKeySpec invertedIndexKey;

    private EdbSecret(SecretKeySpec invertedIndexKey) {
        this.invertedIndexKey = invertedIndexKey;
    }

    private EdbSecret(Parcel in) {
        byte[] invertedIndexKeyBytes = new byte[in.readInt()];
        in.readByteArray(invertedIndexKeyBytes);

        this.invertedIndexKey = new SecretKeySpec(invertedIndexKeyBytes, "AES");

        // SecretKeySpec does an internal copy in its constructor.
        Arrays.fill(invertedIndexKeyBytes, (byte)0x00);
    }

    public static final Creator<EdbSecret> CREATOR = new Creator<EdbSecret>() {
        @Override
        public EdbSecret createFromParcel(Parcel in) {
            return new EdbSecret(in);
        }

        @Override
        public EdbSecret[] newArray(int size) {
            return new EdbSecret[size];
        }
    };

    public static EdbSecret generate(String passphrase, int iterations) {
        Log.i("EdbSecret", "generate");
        byte[] twoLevKey;
        try {
            twoLevKey = MMGlobal.keyGenSI(KEY_BIT_SIZE, passphrase, "salt/salt", iterations);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new EdbException(e);
        }

        return from(twoLevKey);
    }

    public static EdbSecret from(byte[] twoLevKey) {
        return new EdbSecret(new SecretKeySpec(twoLevKey, "AES"));
    }

    public SecretKeySpec getInvertedIndexKey() {
        return invertedIndexKey;
    }

    @Override
    public int describeContents() {
        return 0;
    }

    @Override
    public void writeToParcel(Parcel out, int flags) {
        out.writeInt(invertedIndexKey.getEncoded().length);
        out.writeByteArray(invertedIndexKey.getEncoded());
    }

    public byte[] asEncodedCombined() {
        return Util.combine(invertedIndexKey.getEncoded());
    }
}
