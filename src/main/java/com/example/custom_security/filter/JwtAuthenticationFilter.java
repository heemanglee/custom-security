package com.example.custom_security.filter;

import com.example.custom_security.entity.Member;
import com.example.custom_security.entity.Role;
import com.example.custom_security.security.CustomUserDetails;
import com.example.custom_security.security.jwt.JwtTokenProvider;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@RequiredArgsConstructor
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
        FilterChain filterChain) throws ServletException, IOException {
        String token = parseBearToken(request);

        if (token == null) {
            filterChain.doFilter(request, response);
            return;
        }

        CustomUserDetails user = parseTokenSubject(token);

        UsernamePasswordAuthenticationToken authenticated = UsernamePasswordAuthenticationToken.authenticated(
            user, token, user.getAuthorities());

        // SecurityContextHolder에 인증 정보를 저장
        // Security.getContext().getAuthentication().getPrincipal() 호출 시에 CustomUserDetails 객체를 반환한다.
        SecurityContextHolder.getContext().setAuthentication(authenticated);

        filterChain.doFilter(request, response);
    }

    private String parseBearToken(HttpServletRequest request) {
        String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
        return Optional.ofNullable(authorization)
            .filter(token -> token.substring(0, 7).equalsIgnoreCase("Bearer "))
            .map(token -> token.substring(7))
            .orElse(null);
    }

    private CustomUserDetails parseTokenSubject(String jwtToken) {
        if (jwtToken == null) {
            return null;
        }

        Claims claims = jwtTokenProvider.validateJwtToken(jwtToken);
        if (claims == null) {
            return null;
        }

        String email = claims.getSubject();
        String role = claims.get("auth", String.class);

        // User 객체 생성
        return new CustomUserDetails(new Member(email, "", Role.valueOf(role)));
    }
}
