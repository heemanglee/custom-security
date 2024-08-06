package com.example.custom_security.security;

import com.example.custom_security.entity.Member;
import java.util.Collection;
import java.util.List;
import lombok.AllArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

// UserDetails -> 실제 DB에서 조회한 사용자 정보를 담는 객체
// 여기서는 기존의 UserDetails를 커스텀한 CustomUserDetails를 구현한다.
// @AuthenticationPrincipal를 통해 커스텀한 CustomUserDetails를 사용할 수 있다.
@AllArgsConstructor
public class CustomUserDetails implements UserDetails { // UserDetails를 구현한 CustomUserDetails

    private String email; // principal -> 사용자를 식별하기 위한 고유한 정보
    private String password; // credentials -> 사용자의 비밀번호
    private String role; // authorities -> 사용자의 권한
    private Member member; // 실제 member 객체

    // 사용자의 권한을 리턴한다.
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // 기존의 GrantedAuthority를 커스텀하여 getAuthorities()를 호출할 시에 로그인한 주체의 권한을 명시적으로 보여주도록 한다.
        return List.of(new CustomGrantedAuthority(role)); // member.role = [CustomGrantedAuthority(role=ROLE_USER)]
//        return List.of(() -> role); // member.role = [com.example.custom_security.security.CustomUserDetails$$Lambda$1641/0x0000007001a6f7f0@17fe6f27]
    }

    @Override
    public String getPassword() {
        return password; // 사용자의 비밀번호를 리턴한다.
    }

    @Override
    public String getUsername() {
        return email; // 사용자를 식별하기 위한 고유한 정보(여기서는 email)를 리턴한다.
    }

    @Override
    public boolean isAccountNonExpired() {
        return UserDetails.super.isAccountNonExpired();
    }

    @Override
    public boolean isAccountNonLocked() {
        return UserDetails.super.isAccountNonLocked();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return UserDetails.super.isCredentialsNonExpired();
    }

    @Override
    public boolean isEnabled() {
        return UserDetails.super.isEnabled();
    }

    public Member getMember() {
        return member;
    }
}
