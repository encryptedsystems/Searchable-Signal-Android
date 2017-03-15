package org.thoughtcrime.securesms.database;

import android.content.Context;
import android.support.annotation.Nullable;
import android.util.Log;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;
import com.google.common.collect.TreeMultimap;

import org.clusion.DynRHAndroid;
import org.thoughtcrime.securesms.crypto.MasterCipher;
import org.thoughtcrime.securesms.crypto.MasterSecret;
import org.thoughtcrime.securesms.crypto.MasterSecretUtil;
import org.thoughtcrime.securesms.database.model.DisplayRecord;
import org.thoughtcrime.securesms.database.model.SmsMessageRecord;
import org.whispersystems.libsignal.InvalidMessageException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import javax.crypto.NoSuchPaddingException;

import static org.thoughtcrime.securesms.crypto.MasterSecretUtil.PREFERENCES_NAME;

/**
 * Created by zheguang on 11/16/16.
 */

public class Edb implements Serializable {
    private static final long serialVersionUID = 2L;

    private static int ROW_LIMIT = 500;
    private static String EDB_FILE = "edb_file_" + serialVersionUID;
    private static String EDB_FILE_LEN = "edb_file_len";

    private final HashMap<String, byte[]> emm;

    private Edb(HashMap<String, byte[]> emm) {
        this.emm = emm;
    }

    private static Edb emptyEdb()
    {
        HashMap<String, byte[]> emm = DynRHAndroid.setup();
        return new Edb(emm);
    }

    public static void setupEdb(EncryptingSmsDatabase db, MasterSecret masterSecret) {
        Log.i("Edb", "setupEdb");

        SmsMessageRecord record;
        EncryptingSmsDatabase.Reader reader = null;
        int skip                            = 0;

        Multimap<String,String> word_id_map = ArrayListMultimap.create();

        do {
            if (reader != null)
                reader.close();

            reader = db.getMessages(masterSecret, skip, ROW_LIMIT);

            while ((record = reader.getNext()) != null) {
                DisplayRecord.Body body = record.getBody();
                if (body.isPlaintext()) {
                    putToMap(word_id_map, record.getId(), body.getBody());
                } else {
                    // Should have been decrypted in EncryptingSmsDatabase.DecryptingReader.getBody()
                    throw new EdbException("message should be decrypted.");
                }
            }

            skip += ROW_LIMIT;
        } while (reader.getCount() > 0);

        Edb edb = emptyEdb();
        EdbSecret edbSecret = masterSecret.getEdbSecret();
        if (edbSecret == null) {
            throw new EdbException("EdbSecret has not been generated yet: null");
        }
        // batch update EDB with importing messages
        edb.updateWith(edbSecret, word_id_map);

        db.setEdb(edb);
    }

    private static void putToMap(Multimap<String, String> word_id_map, long message_id, String message_body) {
        String[] words = message_body.replaceAll("\\p{P}", " ").toLowerCase().split("\\s+"); // remove punctuations
        for (String word : words) {
            word_id_map.put(word, String.valueOf(message_id));
        }
    }

    void insertMessage(MasterSecret masterSecret, long message_id, String message_body) {
        EdbSecret edbSecret = masterSecret.getEdbSecret();
        if (edbSecret == null) {
            throw new EdbException("EdbSecret has not been generated yet: null");
        }

        Multimap<String,String> word_id_map = ArrayListMultimap.create();
        putToMap(word_id_map, message_id, message_body);
        updateWith(edbSecret, word_id_map);
    }

    private void updateWith(EdbSecret edbSecret, Multimap<String, String> word_id_map) {
        TreeMultimap<String, byte[]> tokenUp;
        try {
            tokenUp = DynRHAndroid.tokenUpdate(edbSecret.getInvertedIndexKey().getEncoded(), word_id_map);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchProviderException | NoSuchPaddingException | IOException | NoSuchAlgorithmException e) {
            throw new EdbException(e);
        }
        if (tokenUp == null) {
            throw new EdbException("null tokenUp");
        }
        DynRHAndroid.update(emm, tokenUp);
    }

    List<Long> searchMessageIdsFor(MasterSecret masterSecret, String word) {
        List<String> values;
        try {
            EdbSecret edbSecret = masterSecret.getEdbSecret();
            if (edbSecret == null) {
                throw new EdbException("EdbSecret has not been generated yet: null");
            }

            String word_lowercase = word.trim().toLowerCase();

            byte[] sk = edbSecret.getInvertedIndexKey().getEncoded();
            byte[][] token = DynRHAndroid.genTokenFS(sk, word_lowercase);
            values = DynRHAndroid.resolve(sk, DynRHAndroid.queryFS(token, emm), word_lowercase);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            throw new EdbException(e);
        }

        List<Long> message_ids = new ArrayList<>();
        for (String val : values) {
            message_ids.add(Long.parseLong(val));
        }
        return message_ids;
    }

    private static Edb fromBytes(byte[] edbBytes) {
        ByteArrayInputStream bis = new ByteArrayInputStream(edbBytes);
        ObjectInput in = null;
        Edb edb;
        try {
            in = new ObjectInputStream(bis);
            edb = (Edb) in.readObject();
        } catch (IOException | ClassNotFoundException e) {
            throw new EdbException(e);
        } finally {
            try {
                if (in != null) {
                    in.close();
                }
            } catch (IOException ex) {
                Log.w("edb", "ignore close exception", ex);
            }
        }

        if (edb == null) {
            throw new EdbException("null edb");
        }
        return edb;
    }

    private byte[] asBytes() {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutput out = null;
        byte[] res;
        try {
            out = new ObjectOutputStream(bos);
            out.writeObject(this);
            out.flush();
            res = bos.toByteArray();
        } catch (IOException e) {
            throw new EdbException(e);
        } finally {
            try {
                bos.close();
            } catch (IOException ex) {
                Log.w("edb", "ignore close exception", ex);
            }
        }

        if (res == null) {
            throw new EdbException("null edb bytes");
        }
        return res;
    }

    public void saveToSharedPreferences(Context context, MasterSecret masterSecret) {
        MasterCipher cipher = new MasterCipher(masterSecret);
        byte[] edb_encrypted_bytes = cipher.encryptBytes(asBytes());
        MasterSecretUtil.save(context, EDB_FILE, edb_encrypted_bytes);
        MasterSecretUtil.save(context, EDB_FILE_LEN, edb_encrypted_bytes.length);
    }

    public void saveToFile(Context context, MasterSecret masterSecret) {
        try {
            FileOutputStream fos = context.openFileOutput(EDB_FILE, Context.MODE_PRIVATE);
            MasterCipher cipher = new MasterCipher(masterSecret);
            byte[] edb_encrypted_bytes = cipher.encryptBytes(asBytes());
            MasterSecretUtil.save(context, EDB_FILE_LEN, edb_encrypted_bytes.length);
            fos.write(edb_encrypted_bytes);
            fos.close();
        } catch (IOException e) {
            throw new EdbException(e);
        }
    }

    @Nullable
    public static Edb tryRetrieveFromSharedPreferences(Context context, MasterSecret masterSecret) {
        byte[] edb_bytes;
        int edb_bytes_len;
        try {
            edb_bytes = MasterSecretUtil.retrieve(context, EDB_FILE);
            edb_bytes_len = MasterSecretUtil.retrieve(context, EDB_FILE_LEN, -1);
        } catch (IOException e) {
            throw new EdbException(e);
        }
        if (edb_bytes == null) {
            Log.i("Edb", "retrieveFromSharedPreferences: edb not found");
            return null;
        } else if (edb_bytes_len == -1 || edb_bytes_len != edb_bytes.length) {
            Log.e("Edb", "retrieveFromSharedPreferences: edb invalid byte length");
            throw new EdbException("invalid byte length");
        } else {
            Log.i("Edb", "retrieveFromSharedPreferences: edb found");

            MasterCipher cipher = new MasterCipher(masterSecret);
            byte[] edb_decrypted_bytes;
            try {
                edb_decrypted_bytes = cipher.decryptBytes(edb_bytes);
            } catch (InvalidMessageException e) {
                throw new EdbException(e);
            }

            if (edb_decrypted_bytes == null) {
                throw new EdbException("edb decrypted was null");
            }
            return fromBytes(edb_decrypted_bytes);
        }
    }

    @Nullable
    public static Edb tryRetrieveFromFile(Context context, MasterSecret masterSecret) {
        byte[] edb_bytes;
        try {
            FileInputStream fis = context.openFileInput(EDB_FILE);
            int edb_file_len = MasterSecretUtil.retrieve(context, EDB_FILE_LEN, -1);
            if (edb_file_len == -1) {
                throw new EdbException("edb file length not found");
            }
            edb_bytes = new byte[edb_file_len];
            fis.read(edb_bytes);
        } catch (FileNotFoundException e) {
            edb_bytes = null;
        } catch (IOException e) {
            throw new EdbException(e);
        }

        if (edb_bytes == null) {
            Log.i("Edb", "retrieveFromFile: edb not found");
            return null;
        } else {
            Log.i("Edb", "retrieveFromFile: edb found");

            MasterCipher cipher = new MasterCipher(masterSecret);
            byte[] edb_decrypted_bytes;
            try {
                edb_decrypted_bytes = cipher.decryptBytes(edb_bytes);
            } catch (InvalidMessageException e) {
                throw new EdbException(e);
            }

            if (edb_decrypted_bytes == null) {
                throw new EdbException("edb decrypted was null");
            }
            return Edb.fromBytes(edb_decrypted_bytes);
        }
    }

    public static void tryRemoveFromSharedPreferences(Context context) {
        Log.i("Edb", "try remove edb");
        if (!context.getSharedPreferences(PREFERENCES_NAME, 0)
                .edit()
                .remove(EDB_FILE)
                .remove(EDB_FILE_LEN)
                .commit())
        {
            throw new EdbException("failed to remove edb");
        }
    }
}
