package com.spring.securityjwt.configs;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import com.spring.securityjwt.repositories.UserRepository;



@Configuration
public class AppConfigs {
     @Autowired
     private UserRepository userRepository;
     
	@Bean
	public UserDetailsService service() {
		return username -> userRepository.
				findByUsername(username).
				orElseThrow(() -> new UsernameNotFoundException("user " + username + " is not found"));
	}
}
