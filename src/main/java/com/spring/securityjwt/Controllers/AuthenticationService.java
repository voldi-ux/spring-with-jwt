package com.spring.securityjwt.Controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.spring.securityjwt.jwt.JwtService;
import com.spring.securityjwt.repositories.UserRepository;
import com.spring.securityjwt.users.Role;
import com.spring.securityjwt.users.User;

@Service
public class AuthenticationService {
	@Autowired
	private UserRepository userRepository;
	@Autowired
	private JwtService jwtService;
	@Autowired
	private PasswordEncoder encoder;
	@Autowired
	private AuthenticationManager authenticationManager;

	public AuthResponse register(RegisterRequest request) {
		User user = new User();
		user.setFirstname(request.getFirstname());
		user.setLastname(request.getLastname());
		user.setRole(Role.USER);
		user.setEmail(request.getEmail());
		user.setUsername(request.getUsername());
		user.setPassword(encoder.encode(request.getPassword())); // here we are encoding our password
		User savedUser = userRepository.save(user);
		String token = jwtService.generateJwtToken(savedUser);

		return new AuthResponse(token);
	}

	public AuthResponse authenticate(AuthRequest request) {
		UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
				request.getUsername(), request.getPassword());
		User user = (User) authenticationManager.authenticate(authentication).getPrincipal(); // if authentication
																								// fails, spring will
																								// automatically
		// send a response and this function will stop executing from here
		// otherwise the function will continue to run upon successful authentication

		
		String token = jwtService.generateJwtToken(user);

		return new AuthResponse(token);
	}

}
