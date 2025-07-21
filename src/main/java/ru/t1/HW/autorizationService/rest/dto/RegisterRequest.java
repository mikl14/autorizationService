package ru.t1.HW.autorizationService.rest.dto;

import lombok.Getter;
import lombok.Setter;
import ru.t1.HW.autorizationService.entities.Role;

@Getter
@Setter
public class RegisterRequest extends AuthRequest{
    private String email;
    private Role role;
}
