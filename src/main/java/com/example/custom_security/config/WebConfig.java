package com.example.custom_security.config;

import com.example.custom_security.security.CurrentUserHandlerMethodArgumentResolver;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
@RequiredArgsConstructor
public class WebConfig implements WebMvcConfigurer {

    private final CurrentUserHandlerMethodArgumentResolver currentUserHandlerMethodArgumentResolver;

    // 커스텀한 HandlerMethodArgumentResolver를 추가한다.
    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
        resolvers.add(currentUserHandlerMethodArgumentResolver);
    }
}