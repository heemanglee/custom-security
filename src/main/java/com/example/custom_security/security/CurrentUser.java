package com.example.custom_security.security;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.springframework.security.core.annotation.AuthenticationPrincipal;

@Target(ElementType.PARAMETER) // 어노테이션이 적용될 수 있는 대상을 지정
@Retention(RetentionPolicy.RUNTIME) // 런타임동안 어노테이션 정보를 유지
@AuthenticationPrincipal // 현재 인증된 사용자를 참조하는데 사용
public @interface CurrentUser {
}