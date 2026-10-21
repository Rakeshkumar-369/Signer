package in.signer.server;

import in.signer.server.cli.LicenseTool;
import in.signer.server.config.SignerProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.scheduling.annotation.EnableScheduling;

import java.util.Arrays;
import java.util.TimeZone;

@SpringBootApplication
@EnableScheduling
@EnableConfigurationProperties(SignerProperties.class)
public class SignerServerApplication {

    public static void main(String[] args) throws Exception {
        if (args.length > 0 && "license".equals(args[0])) {
            LicenseTool.run(Arrays.copyOfRange(args, 1, args.length));
            return;
        }
        // All timestamps are stored and compared in UTC.
        TimeZone.setDefault(TimeZone.getTimeZone("UTC"));
        SpringApplication.run(SignerServerApplication.class, args);
    }
}
