package com.spring.securityjwt;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@SpringBootApplication
public class SecurityJwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecurityJwtApplication.class, args);
	}
}
