package ru.t1.HW.autorizationService.rest.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AuthResponse extends TokenRefreshRequest{
    private String token;

    public AuthResponse(String token, String refreshToken) {
        super(refreshToken);
        this.token = token;
    }
}
