package com.spring.securityjwt.Controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {
     @Autowired
      private AuthenticationService authenticationService;
     
	@PostMapping("/register")
	public ResponseEntity<AuthResponse> register(@RequestBody RegisterRequest request) {
		return ResponseEntity.ok(authenticationService.register(request)); 
	}
	
	
	@PostMapping("/authenticate")
	public ResponseEntity<AuthResponse> register(@RequestBody AuthRequest request) {
		return ResponseEntity.ok(authenticationService.authenticate(request));	
	}
	
}
