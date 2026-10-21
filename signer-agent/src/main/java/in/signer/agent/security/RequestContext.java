package in.signer.agent.security;

import in.signer.core.token.TransactionToken;

/** Who is asking: the browser origin and, in token mode, the verified transaction token. */
public record RequestContext(String origin, TransactionToken token) {

    public String txn() {
        return token == null ? null : token.txn();
    }

    public String organisation() {
        return token == null ? null : token.tenantName();
    }

    public String reference() {
        return token == null ? null : token.reference();
    }
}
