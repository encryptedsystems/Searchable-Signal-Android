package org.thoughtcrime.securesms;

import android.support.annotation.NonNull;

import org.thoughtcrime.securesms.crypto.MasterCipher;
import org.thoughtcrime.securesms.crypto.MasterSecret;
import org.thoughtcrime.securesms.database.model.MessageRecord;

import java.util.Locale;
import java.util.Set;

public interface BindableSearchResultListItem extends Unbindable {

  public void bind(@NonNull MasterSecret masterSecret, @NonNull MasterCipher masterCipher, @NonNull MessageRecord record,
                   @NonNull Locale locale, @NonNull Set<Long> selectedThreads, boolean batchMode);
}
