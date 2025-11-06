package pedro.login.loginJWT.repository;


import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.core.userdetails.UserDetails;

import pedro.login.loginJWT.domain.User;

public interface UserRepository extends JpaRepository<User, String>{
	
	UserDetails findByLogin(String login);
}
