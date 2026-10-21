package in.signer.server.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/** Typed view of the {@code signer.*} configuration. */
@ConfigurationProperties(prefix = "signer")
public class SignerProperties {

    private String dataDir = "./data";
    private String publicUrl = "http://localhost:8080";
    private String issuer = "signer-server";
    private int maxRequestMb = 40;
    private final Token token = new Token();
    private final Sessions sessions = new Sessions();
    private final Tsa tsa = new Tsa();
    private final Verification verification = new Verification();
    private final Admin admin = new Admin();
    private final License license = new License();
    private final Demo demo = new Demo();

    public static class Token {
        private String keyFile = "./data/keys/token-signing.pem";
        private String additionalPublicKeys = "";
        private int defaultTtlSeconds = 300;
        private int maxTtlSeconds = 1800;
        private int maxDocuments = 100;

        public String getKeyFile() { return keyFile; }
        public void setKeyFile(String v) { keyFile = v; }
        public String getAdditionalPublicKeys() { return additionalPublicKeys; }
        public void setAdditionalPublicKeys(String v) { additionalPublicKeys = v; }
        public int getDefaultTtlSeconds() { return defaultTtlSeconds; }
        public void setDefaultTtlSeconds(int v) { defaultTtlSeconds = v; }
        public int getMaxTtlSeconds() { return maxTtlSeconds; }
        public void setMaxTtlSeconds(int v) { maxTtlSeconds = v; }
        public int getMaxDocuments() { return maxDocuments; }
        public void setMaxDocuments(int v) { maxDocuments = v; }
    }

    public static class Sessions {
        private int ttlMinutes = 30;
        private int maxPdfMb = 25;

        public int getTtlMinutes() { return ttlMinutes; }
        public void setTtlMinutes(int v) { ttlMinutes = v; }
        public int getMaxPdfMb() { return maxPdfMb; }
        public void setMaxPdfMb(int v) { maxPdfMb = v; }
    }

    public static class Tsa {
        private String url = "";
        private String username = "";
        private String password = "";

        public String getUrl() { return url; }
        public void setUrl(String v) { url = v; }
        public String getUsername() { return username; }
        public void setUsername(String v) { username = v; }
        public String getPassword() { return password; }
        public void setPassword(String v) { password = v; }
    }

    public static class Verification {
        private String trustAnchorsDir = "./data/trust";
        private boolean checkRevocation = false;
        private boolean fetchIssuers = false;

        public String getTrustAnchorsDir() { return trustAnchorsDir; }
        public void setTrustAnchorsDir(String v) { trustAnchorsDir = v; }
        public boolean isCheckRevocation() { return checkRevocation; }
        public void setCheckRevocation(boolean v) { checkRevocation = v; }
        public boolean isFetchIssuers() { return fetchIssuers; }
        public void setFetchIssuers(boolean v) { fetchIssuers = v; }
    }

    public static class Admin {
        private String initialUsername = "admin";
        private String initialPassword = "";
        private int sessionHours = 8;

        public String getInitialUsername() { return initialUsername; }
        public void setInitialUsername(String v) { initialUsername = v; }
        public String getInitialPassword() { return initialPassword; }
        public void setInitialPassword(String v) { initialPassword = v; }
        public int getSessionHours() { return sessionHours; }
        public void setSessionHours(int v) { sessionHours = v; }
    }

    public static class License {
        private String file = "./data/license.lic";

        public String getFile() { return file; }
        public void setFile(String v) { file = v; }
    }

    public static class Demo {
        private boolean enabled = true;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean v) { enabled = v; }
    }

    public String getDataDir() { return dataDir; }
    public void setDataDir(String v) { dataDir = v; }
    public String getPublicUrl() { return publicUrl; }
    public void setPublicUrl(String v) { publicUrl = v; }
    public String getIssuer() { return issuer; }
    public void setIssuer(String v) { issuer = v; }
    public int getMaxRequestMb() { return maxRequestMb; }
    public void setMaxRequestMb(int v) { maxRequestMb = v; }
    public Token getToken() { return token; }
    public Sessions getSessions() { return sessions; }
    public Tsa getTsa() { return tsa; }
    public Verification getVerification() { return verification; }
    public Admin getAdmin() { return admin; }
    public License getLicense() { return license; }
    public Demo getDemo() { return demo; }
}
