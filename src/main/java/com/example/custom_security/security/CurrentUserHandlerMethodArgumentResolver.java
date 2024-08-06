package com.example.custom_security.security;

import com.example.custom_security.entity.Member;
import org.springframework.core.MethodParameter;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

// Member 클래스에 @CurrentUser를 사용하여, 인증된 현재 사용자의 정보를 매핑하는 HandlerMethodArgumentResolver
@Component
public class CurrentUserHandlerMethodArgumentResolver implements HandlerMethodArgumentResolver {

    // 현재 resolver가 특정 파라미터를 지원하는지 확인하는 메서드
    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return parameter.hasParameterAnnotation(CurrentUser.class) && // 파라미터가 @CurrentUser 애너테이션을 사용하고,
            parameter.getParameterType().equals(Member.class); // @CurrentUser 애너테이션을 사용하는 파라미터 타입이 Member 클래스인 경우 true 반환
    }

    // supportsParameter()가 true를 반환하는 경우, 실제 바인딩할 객체를 반환하는 메서드
    @Override
    public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mavContainer, NativeWebRequest webRequest, WebDataBinderFactory binderFactory) throws Exception {
        // SecurityContext에 저장된 Authentication 객체에서 principal(UserDetails)을 가져온다.
        CustomUserDetails userDetails = (CustomUserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return userDetails.getMember(); // CustomUserDetails에 저장된 Member 객체를 반환한다.
    }
}
