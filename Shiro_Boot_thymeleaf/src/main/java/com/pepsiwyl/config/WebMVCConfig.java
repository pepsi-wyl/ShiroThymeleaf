package com.pepsiwyl.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;


/**
 * @author by pepsi-wyl
 * @date 2022-04-16 14:41
 */

@Configuration
public class WebMVCConfig implements WebMvcConfigurer {

    /**
     * ViewControllers
     *
     * @param registry
     */
    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController("/").setViewName("login");
        registry.addViewController("/toLogin").setViewName("login");
        registry.addViewController("/toRegister").setViewName("register");
        registry.addViewController("/toIndex").setViewName("index");
    }

}
