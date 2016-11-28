package org.thoughtcrime.securesms.database;

import android.content.Context;
import android.support.annotation.Nullable;
import android.util.Log;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;

import org.crypto.sse.EdbException;
import org.crypto.sse.MMGlobal;
import org.thoughtcrime.securesms.crypto.MasterSecret;
import org.thoughtcrime.securesms.crypto.MasterSecretUtil;
import org.thoughtcrime.securesms.database.model.DisplayRecord;
import org.thoughtcrime.securesms.database.model.SmsMessageRecord;

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
import java.io.StreamCorruptedException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;

import javax.crypto.NoSuchPaddingException;

import static org.crypto.sse.MMGlobal.testSI;

/**
 * Created by zheguang on 11/16/16.
 */

public class Edb implements Serializable {
    public static int ROW_LIMIT = 500;
    public static String EDB_FILE = "edb_file";
    public static String EDB_FILE_LEN = "edb_file_len";

    public final MMGlobal two_lev;

    private Edb(MMGlobal two_lev) {
        this.two_lev = two_lev;
    }

    public static void setupEdb(EncryptingSmsDatabase db, MasterSecret masterSecret) {
        Log.i("Edb", "setupEdb");

        //EncryptingSmsDatabase db = DatabaseFactory.getEncryptingSmsDatabase(context);
        SmsMessageRecord record;
        EncryptingSmsDatabase.Reader reader = null;
        int skip                            = 0;

        Multimap<String,String> word_id_map = ArrayListMultimap.create();

        do {
            Log.i("edb", "loop");
            if (reader != null)
                reader.close();

            reader = db.getMessages(masterSecret, skip, ROW_LIMIT);

            while ((record = reader.getNext()) != null) {
                Log.i("edb", "read loop");
                Log.i("edb.recipient", record.getIndividualRecipient().getName() + ", " + record.getIndividualRecipient().getNumber());
                DisplayRecord.Body body = record.getBody();
                if (body.isPlaintext()) {
                    String message_id = String.valueOf(record.getId());
                    String message_body = body.getBody();
                    String[] words = message_body.replaceAll("\\p{P}", " ").toLowerCase().split("\\s+"); // remove punctuations
                    for (String word : words) {
                        word_id_map.put(word, message_id);
                    }
                } else {
                    // Should have been decrypted in EncryptingSmsDatabase.DecryptingReader.getBody()
                    throw new EdbException("message should be decrypted.");
                }
            }

            skip += ROW_LIMIT;
        } while (reader.getCount() > 0);


        //byte[] secret = masterSecret.getEncryptionKey().getEncoded();
        //List<byte[]> secrets = new ArrayList<>();
        //secrets.add(secret);

        int bigBlock = 1000;
        int smallBlock = 100;
        int dataSize = 10000;

        Edb edb;
        try {
            //List<byte[]> secrets= IEX2Lev.keyGen(256, "samzhao", "salt/salt", 100);
            //MMGlobal two_lev = MMGlobal.constructEMMParGMM(secrets.get(0), word_id_map, bigBlock, smallBlock, dataSize);
            EdbSecret edbSecret = masterSecret.getEdbSecret();
            if (edbSecret == null) {
                throw new EdbException("EdbSecret has not been generated yet: null");
            }
            MMGlobal two_lev = MMGlobal.constructEMMParGMM(edbSecret.getInvertedIndexKey().getEncoded(), word_id_map, bigBlock, smallBlock, dataSize);
            edb = new Edb(two_lev);
        } catch (InterruptedException | ExecutionException | IOException e) {
            throw new EdbException(e);
        }

        db.setEdb(edb);
    }

    public List<Long> searchMessageIdsFor(MasterSecret masterSecret, String word) {
        // TODO: use provided masterSecret to retrieve Edb secrets
        List<String> values;
        try {
            EdbSecret edbSecret = masterSecret.getEdbSecret();
            if (edbSecret == null) {
                throw new EdbException("EdbSecret has not been generated yet: null");
            }
            byte[][] token = MMGlobal.genToken(edbSecret.getInvertedIndexKey().getEncoded(), word);
            values = testSI(token, two_lev.getDictionary(), two_lev.getArray());
        } catch (IOException | NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            throw new EdbException(e);
        }

        List<Long> message_ids = new ArrayList<>();
        for (String val : values) {
            message_ids.add(Long.parseLong(val));
        }
        return message_ids;
    }

    public static Edb fromBytes(byte[] edbBytes) {
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
                // ignore close exception
            }
        }

        if (edb == null) {
            throw new EdbException("null edb");
        }
        return edb;
    }

    public byte[] asBytes() {
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
                // ignore close exception
            }
        }

        if (res == null) {
            throw new EdbException("null edb bytes");
        }
        return res;
    }

    public void saveToSharedPreferences(Context context) {
        MasterSecretUtil.save(context, "edb", asBytes());
    }

    public void saveToFile(Context context) {
        try {
            FileOutputStream fos = context.openFileOutput(EDB_FILE, Context.MODE_PRIVATE);
            byte[] edb_bytes = asBytes();
            MasterSecretUtil.save(context, EDB_FILE_LEN, edb_bytes.length);
            fos.write(asBytes());
            fos.close();
        } catch (IOException e) {
            throw new EdbException(e);
        }
    }

    @Nullable
    public static Edb tryRetrieveFromSharedPreferences(Context context) {
        byte[] edb_bytes;
        try {
            edb_bytes = MasterSecretUtil.retrieve(context, "edb");
        } catch (IOException e) {
            throw new EdbException(e);
        }
        if (edb_bytes == null) {
            Log.i("Edb", "retrieveFromSharedPreferences: edb not found");
            return null;
        }
        else {
            Log.i("Edb", "retrieveFromSharedPreferences: edb found");
            return fromBytes(edb_bytes);
        }
    }

    @Nullable
    public static Edb tryRetrieveFromFile(Context context) {
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
            return Edb.fromBytes(edb_bytes);
        }
    }
}
