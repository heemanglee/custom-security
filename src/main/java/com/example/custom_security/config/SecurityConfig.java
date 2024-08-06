package com.example.custom_security.config;

import com.example.custom_security.filter.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
@EnableWebSecurity // security 적용
@RequiredArgsConstructor
@EnableMethodSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
            .csrf(
                csrfConfig -> {
                    csrfConfig.ignoringRequestMatchers("/h2-console/**") // h2-console 접근 시 csrf 무시
                        .disable(); // csrf 비활성화
                }
            )
            .headers().frameOptions().disable() // h2-console 접근 시 frameOptions 비활성화
            .and()
            .authorizeHttpRequests(
                authorizeConfig -> {
                    authorizeConfig
                        .requestMatchers("/h2-console/**").permitAll() // h2-console 인증 없이 접근 허용
                        .requestMatchers("/login", "/register", "/home").permitAll() // /login, /register 인증 없이 접근 허용
                        .requestMatchers(HttpMethod.GET, "/authorization-user").hasAnyRole("USER", "ADMIN") // /authorization-user 요청은 USER 또는 ADMIN 권한이 있어야 접근 가능
                        .requestMatchers(HttpMethod.GET, "/authorization-admin").hasRole("ADMIN") // /authorization-admin 요청은 ADMIN 권한이 있어야 접근 가능
                        .anyRequest().authenticated(); // 나머지 요청은 인증 필요
                }
            )
//            .formLogin( // form login 설정
//                formLoginConfig -> {
//                    formLoginConfig
//                        .loginPage("/login") // 커스텀 로그인 페이지 (설정하지 않으면 시큐리티 기본 로그인 페이지가 나옴)
//                        .loginProcessingUrl("/login") // 로그인을 처리하는 URL
//                        .defaultSuccessUrl("/home", true) // 로그인 성공 시 이동할 URL
//                        .failureUrl("/login") // 로그인 실패 시 이동할 URL
//                        .usernameParameter("email") // security.core.userdetails.UserDetails의 username에 해당하는 파라미터 -> principal
//                        .passwordParameter("password"); // security.core.userdetails.UserDetails의 password에 해당하는 파라미터 -> credentials
//                }
//            )
            .logout( // logout 설정
                logoutConfig -> {
                    logoutConfig
                        .logoutUrl("/logout") // 로그아웃을 처리하는 URL
                        .deleteCookies("JSESSIONID") // 로그아웃 시 삭제할 쿠키
                        .logoutSuccessUrl("/home"); // 로그아웃 성공 시 이동할 URL
                }
            )
            .sessionManagement(sessionManagement -> {
                sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
            })
            .addFilterBefore(jwtAuthenticationFilter, BasicAuthenticationFilter.class);

        return httpSecurity.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(); // bcrypt 암호화 방식 사용
    }
}
