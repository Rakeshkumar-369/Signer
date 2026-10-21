package in.signer.server.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addRedirectViewController("/", "/admin/");
        registry.addRedirectViewController("/admin", "/admin/");
        registry.addRedirectViewController("/demo", "/demo/");
        registry.addViewController("/admin/").setViewName("forward:/admin/index.html");
        registry.addViewController("/demo/").setViewName("forward:/demo/index.html");
    }
}
