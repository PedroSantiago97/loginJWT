package pedro.login.loginJWT.security;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import pedro.login.loginJWT.repository.UserRepository;
import pedro.login.loginJWT.service.TokenService;


@Component
public class SecurityFilter extends OncePerRequestFilter{
	
	@Autowired
	TokenService tokenService;
	
	@Autowired
	UserRepository userRepository;
	

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
			var token = recoverToken(request);
			if(token != null && !token.isBlank()) {
				var login = tokenService.validateToken(token);
				if(login != null) {
					var user = userRepository.findByLogin(login);
					if(user != null) {
						var authentication  = new UsernamePasswordAuthenticationToken(user,null,user.getAuthorities());
						SecurityContextHolder.getContext().setAuthentication(authentication);
					}
				}
			}
			
			filterChain.doFilter(request, response);
		
	}
	
	private String recoverToken(HttpServletRequest request) {
		var authHeader = request.getHeader("Authorization");
		if(authHeader == null || !authHeader.startsWith("Bearer ")) return null;
		return authHeader.replace("Bearer ", "");
	}

}
