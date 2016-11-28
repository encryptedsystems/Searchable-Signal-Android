package org.thoughtcrime.securesms.database.loaders;

import android.content.Context;
import android.database.Cursor;
import android.util.Log;

import org.thoughtcrime.securesms.crypto.MasterSecret;
import org.thoughtcrime.securesms.database.DatabaseFactory;
import org.thoughtcrime.securesms.database.EncryptingSmsDatabase;
import org.thoughtcrime.securesms.service.KeyCachingService;
import org.thoughtcrime.securesms.util.AbstractCursorLoader;

import java.util.List;

public class ConversationLoader extends AbstractCursorLoader {
  private final long threadId;
  private       long limit;
  private String queryFilter;

  public ConversationLoader(Context context, long threadId, long limit, String queryFilter) {
    super(context);
    this.threadId = threadId;
    this.limit  = limit;
    this.queryFilter = queryFilter;
  }

  public boolean hasLimit() {
    return limit > 0;
  }

  @Override
  public Cursor getCursor() {
    Log.i("ConversationLoader", "getCursor with filter: " + queryFilter);
    if (queryFilter == null || queryFilter.trim().equals("")) {
      return DatabaseFactory.getMmsSmsDatabase(context).getConversation(threadId, limit);
    } else {
      if (DatabaseFactory.getEncryptingSmsDatabase(context).getEdb() != null) {
        Log.i("ConversationLoader", "edb: not null");
        MasterSecret masterSecret = KeyCachingService.getMasterSecret(context);
        List<Long> message_ids = DatabaseFactory.getEncryptingSmsDatabase(context).getMessageIdsFromWord(masterSecret, queryFilter);
        return DatabaseFactory.getMmsSmsDatabase(context).getConversation(threadId, limit, message_ids);
      } else {
        Log.i("ConversationLoader", "edb: null");
        return DatabaseFactory.getMmsSmsDatabase(context).getConversation(threadId, limit);
      }
    }
  }
}
