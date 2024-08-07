package com.example.custom_security.security;

import com.example.custom_security.entity.Member;
import java.util.Collection;
import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

// UserDetails -> 실제 DB에서 조회한 사용자 정보를 담는 객체
// 여기서는 기존의 UserDetails를 커스텀한 CustomUserDetails를 구현한다.
// @AuthenticationPrincipal를 통해 커스텀한 CustomUserDetails를 사용할 수 있다.
@AllArgsConstructor
@Getter
public class CustomUserDetails implements UserDetails { // UserDetails를 구현한 CustomUserDetails

    private Member member; // 실제 member 객체

    // 사용자의 권한을 리턴한다.
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new CustomGrantedAuthority(member.getRole().getName())); // 사용자의 권한을 리턴한다.
    }

    @Override
    public String getPassword() {
        return member.getPassword(); // 사용자의 비밀번호를 리턴한다.
    }

    @Override
    public String getUsername() {
        return member.getEmail(); // 사용자를 식별하기 위한 고유한 정보(여기서는 email)를 리턴한다.
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

}
