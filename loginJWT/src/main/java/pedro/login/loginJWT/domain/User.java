package pedro.login.loginJWT.domain;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

@Table(name = "users")
@Entity(name = "users")
@Data
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(of = "id")

public class User implements UserDetails{
	
	@Id
	@GeneratedValue(strategy = GenerationType.UUID)
	private UUID id;
	private String login;
	private String password;
	@Enumerated(EnumType.STRING)
	@Column(nullable = false)
	private UserRole role;
	
	
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		//Um list.of Somente, 2 SimpleGrantedAuthority !!!
		if(this.role == UserRole.ADMIN) return List.of(new SimpleGrantedAuthority("ROLE_ADMIN"), new SimpleGrantedAuthority("ROLE_USER"));
		
		else return List.of(new SimpleGrantedAuthority("ROLE_USER"));
	}
	
	public User(String login, String password) {
		this.login = login;
		this.password = password;
		this.role = UserRole.USER;
		
	}
	
	@Override
	public String getUsername() {
		
		return login;
	}
	
	@Override

	public boolean isAccountNonExpired() {

		return true;

	}

	@Override

	public boolean isAccountNonLocked() {

		return true;

	}

	@Override

	public boolean isCredentialsNonExpired() {

		return true;

	}

	@Override

	public boolean isEnabled() {

		return true;

	}
}
