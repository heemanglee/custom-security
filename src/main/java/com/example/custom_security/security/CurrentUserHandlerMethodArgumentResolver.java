package com.example.custom_security.security;

import com.example.custom_security.entity.Member;
import org.springframework.core.MethodParameter;
import org.springframework.security.core.Authentication;
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
    // 아래의 경우 @CurrentUser 애너테이션을 사용하는 파라미터에 Member 객체를 바인딩한다.
    @Override
    public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mavContainer, NativeWebRequest webRequest, WebDataBinderFactory binderFactory) throws Exception {

        // 인증되지 않은 사용자라면 null을 반환한다.
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        /**
         * SecurityContextHolder.getContext().getAuthentication()은 현재 사용자의 인증 정보를 가져온다.
         * 인증되지 않은 사용자라면 null을 반환한다.
         * ----------------------------------------------------------------------------------------------------
         * authentication.isAuthenticated() : 사용자가 인증되었는지 여부를 반환한다.
         * 인증되지 않은 사용자라면 false를 반환한다.
         * ----------------------------------------------------------------------------------------------------
         * authentication.getPrincipal().equals("anonymousUser") : 사용자가 익명 사용자인지 여부를 반환한다.
         * 인증되지 않은 사용자로 인식될 때, authentication.getPrincipal()은 "anonymousUser" 문자열을 반환할 수 있다.
         */
        if (authentication == null || !authentication.isAuthenticated() || authentication.getPrincipal().equals("anonymousUser")) {
            return null; // null 객체 반환
        }

        // SecurityContext에 저장된 Authentication 객체에서 principal(UserDetails)을 가져온다.
        // JwtAuthenticationFilter에서 SecurityContextHolder.getContext().setAuthentication(authenticated)로 저장한 CustomUserDetails 객체를 가져온다
        // UserDetails를 구현한 CustomUserDetails 객체를 가져온다.
        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
        return userDetails.getMember(); // CustomUserDetails에 저장된 Member 객체를 반환한다.
    }
}
