package com.example.custom_security.dto;

import com.example.custom_security.entity.Member;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class GetUserInfoResponse {

    private String email;
    private String role;

    public static GetUserInfoResponse of(Member member) {
        return new GetUserInfoResponse(member.getEmail(), member.getRole().getName());
    }
}
