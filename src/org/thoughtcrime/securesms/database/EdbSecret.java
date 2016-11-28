package org.thoughtcrime.securesms.database;

import android.os.Parcel;
import android.os.Parcelable;
import android.util.Log;

import org.crypto.sse.EdbException;
import org.crypto.sse.IEX2Lev;
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
    public static final int NUM_KEYS = 3;
    private final SecretKeySpec invertedIndexKey;
    private final SecretKeySpec indexKey;
    private final SecretKeySpec encryptionKey;

    private EdbSecret(SecretKeySpec invertedIndexKey, SecretKeySpec indexKey, SecretKeySpec encryptionKey) {
        this.invertedIndexKey = invertedIndexKey;
        this.indexKey = indexKey;
        this.encryptionKey = encryptionKey;
    }

    private EdbSecret(Parcel in) {
        byte[] invertedIndexKeyBytes = new byte[in.readInt()];
        in.readByteArray(invertedIndexKeyBytes);

        byte[] indexKeyBytes = new byte[in.readInt()];
        in.readByteArray(indexKeyBytes);

        byte[] encryptionKeyBytes = new byte[in.readInt()];
        in.readByteArray(encryptionKeyBytes);

        this.invertedIndexKey = new SecretKeySpec(invertedIndexKeyBytes, "AES");
        this.indexKey = new SecretKeySpec(indexKeyBytes, "AES");
        this.encryptionKey = new SecretKeySpec(encryptionKeyBytes, "AES");

        // SecretKeySpec does an internal copy in its constructor.
        Arrays.fill(invertedIndexKeyBytes, (byte)0x00);
        Arrays.fill(indexKeyBytes, (byte)0x00);
        Arrays.fill(encryptionKeyBytes, (byte) 0x00);
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
        List<byte[]> twoLevKeys;
        try {
            twoLevKeys = IEX2Lev.keyGen(KEY_BIT_SIZE, passphrase, "salt/salt", iterations);
            Log.i("EdbSecret", "generate twoLevKeys lengths: " + twoLevKeys.get(0).length + ", " + twoLevKeys.get(1).length + ", " + twoLevKeys.get(2).length);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new EdbException(e);
        }

        return from(twoLevKeys);
    }

    public static EdbSecret from(List<byte[]> twoLevKeys) {
        if (twoLevKeys.size() != NUM_KEYS) {
            throw new EdbException("wrong number of two-lev keys: expected=" + NUM_KEYS + ", actual=" + twoLevKeys.size());
        }

        return new EdbSecret(
                new SecretKeySpec(twoLevKeys.get(0), "AES"),
                new SecretKeySpec(twoLevKeys.get(1), "AES"),
                new SecretKeySpec(twoLevKeys.get(2), "AES")
        );
    }

    public SecretKeySpec getInvertedIndexKey() {
        return invertedIndexKey;
    }

    public SecretKeySpec getIndexKey() {
        return indexKey;
    }

    public SecretKeySpec getEncryptionKey() {
        return encryptionKey;
    }

    @Override
    public int describeContents() {
        return 0;
    }

    @Override
    public void writeToParcel(Parcel out, int flags) {
        out.writeInt(invertedIndexKey.getEncoded().length);
        out.writeByteArray(invertedIndexKey.getEncoded());

        out.writeInt(indexKey.getEncoded().length);
        out.writeByteArray(indexKey.getEncoded());

        out.writeInt(encryptionKey.getEncoded().length);
        out.writeByteArray(encryptionKey.getEncoded());
    }

    public byte[] asEncodedCombined() {
        return Util.combine(invertedIndexKey.getEncoded(), indexKey.getEncoded(), encryptionKey.getEncoded());
    }
}
