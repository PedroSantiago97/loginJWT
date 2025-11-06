package pedro.login.loginJWT.domain.DTOs;

import pedro.login.loginJWT.domain.UserRole;

public record RegisterDTO(String login, String password, UserRole role) {

}
