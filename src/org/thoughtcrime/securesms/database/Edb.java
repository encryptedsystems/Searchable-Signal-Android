package org.thoughtcrime.securesms.database;

import android.content.Context;
import android.os.Environment;
import android.util.Log;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;

import org.crypto.sse.EdbException;
import org.crypto.sse.IEX2Lev;
import org.crypto.sse.MMGlobal;
import org.thoughtcrime.securesms.BuildConfig;
import org.thoughtcrime.securesms.crypto.MasterSecret;
import org.thoughtcrime.securesms.database.model.DisplayRecord;
import org.thoughtcrime.securesms.database.model.SmsMessageRecord;
import org.thoughtcrime.securesms.util.ParcelUtil;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.regex.Pattern;

import javax.crypto.NoSuchPaddingException;

import static org.crypto.sse.MMGlobal.testSI;

/**
 * Created by zheguang on 11/16/16.
 */

public class Edb {
    public static int ROW_LIMIT = 500;

    public MMGlobal two_lev;
    public List<byte[]> secrets;  // TODO: moved these keys to KeyCachingService

    private Edb(MMGlobal two_lev, List<byte[]> secrets) {
        this.two_lev = two_lev;
        this.secrets = secrets; // TODO: moved these keys to KeyCachingService
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
            // TODO: use serialized masterSecret as the input password
            List<byte[]> secrets= IEX2Lev.keyGen(256, "samzhao", "salt/salt", 100);
            MMGlobal two_lev = MMGlobal.constructEMMParGMM(secrets.get(0), word_id_map, bigBlock, smallBlock, dataSize);
            edb = new Edb(two_lev, secrets);
        } catch (InterruptedException | ExecutionException | IOException | NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
            throw new EdbException(e);
        }

        db.setEdb(edb);
    }

    public List<Long> searchMessageIdsFor(MasterSecret masterSecret, String word) {
        // TODO: use provided masterSecret to retrieve Edb secrets
        List<String> values;
        try {
            byte[][] token = MMGlobal.genToken(secrets.get(0), word);
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
}
