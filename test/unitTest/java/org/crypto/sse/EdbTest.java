package org.crypto.sse;

import junit.framework.Assert;

import org.junit.Before;
import org.junit.Test;
import org.thoughtcrime.securesms.BaseUnitTest;
import org.thoughtcrime.securesms.crypto.MasterSecret;
import org.thoughtcrime.securesms.database.Edb;
import org.thoughtcrime.securesms.database.EncryptingSmsDatabase;
import org.thoughtcrime.securesms.database.model.DisplayRecord;
import org.thoughtcrime.securesms.database.model.SmsMessageRecord;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.List;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Created by zheguang on 11/17/16.
 */

public class EdbTest extends BaseUnitTest {

    private EncryptingSmsDatabase db;
    private MasterSecret masterSecret;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();

        db = mock(EncryptingSmsDatabase.class);
        EncryptingSmsDatabase.DecryptingReader reader = mock(EncryptingSmsDatabase.DecryptingReader.class);
        SmsMessageRecord[] smss = new SmsMessageRecord[] {
                smsOf(10, "hello, world! This is from Brown."),
                smsOf(11, "Brown University, RI 02912"),
        };
        when(reader.getNext()).thenReturn(smss[0], smss[1], null); // use null to end the read
        when(reader.getCount()).thenReturn(0);

        when(db.getMessages(any(MasterSecret.class), anyInt(), anyInt())).thenReturn(reader);
        doNothing().when(db).setEdb(any(Edb.class));
    }

    private SmsMessageRecord smsOf(long message_id, String message_body) {
        SmsMessageRecord res = mock(SmsMessageRecord.class);
        when(res.getBody()).thenReturn(new DisplayRecord.Body(message_body, true));
        when(res.getId()).thenReturn(message_id);
        return res;
    }

    @Test
    public void testTwoLev() throws EdbException, IOException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException, InvalidKeyException, InvalidKeySpecException {
        Edb.setupEdb(db, masterSecret);

        Edb edb = db.getEdb();

        String keyword = "world";
        byte[][] token = MMGlobal.genToken(masterSecret.getEdbSecret().getInvertedIndexKey().getEncoded(), keyword);
        List<String> ids = MMGlobal.testSI(token, edb.two_lev.getDictionary(), edb.two_lev.getArray());
        List<String> expected = Arrays.asList("10");
        Assert.assertEquals(ids, expected);
    }
}
