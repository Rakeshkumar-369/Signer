package in.signer.agent.security;

import in.signer.core.ErrorCode;
import in.signer.core.SignerException;

import java.time.Instant;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** Tracks how many documents each transaction token has signed, so a token cannot be re-used beyond its limit. */
public final class ReplayCache {

    private record Usage(int used, Instant expires) {
    }

    private final Map<String, Usage> usage = new ConcurrentHashMap<>();

    /** Reserves {@code count} documents for {@code txn}; throws when the token's allowance would be exceeded. */
    public synchronized void consume(String txn, int count, int max, Instant expires) {
        purge();
        Usage u = usage.getOrDefault(txn, new Usage(0, expires));
        if (u.used + count > Math.max(1, max)) {
            throw new SignerException(ErrorCode.TOKEN_REPLAYED,
                    "This transaction token has already been used; request a new token for each signing transaction");
        }
        usage.put(txn, new Usage(u.used + count, expires.plusSeconds(300)));
    }

    /** Returns documents to the allowance when signing failed before anything was produced. */
    public synchronized void refund(String txn, int count) {
        usage.computeIfPresent(txn, (k, u) -> new Usage(Math.max(0, u.used - count), u.expires));
    }

    private void purge() {
        Instant now = Instant.now();
        for (Iterator<Map.Entry<String, Usage>> it = usage.entrySet().iterator(); it.hasNext(); ) {
            if (it.next().getValue().expires.isBefore(now)) {
                it.remove();
            }
        }
    }
}
