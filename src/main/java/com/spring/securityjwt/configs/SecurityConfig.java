package com.spring.securityjwt.configs;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.spring.securityjwt.filters.JwtAuthFilter;



@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Autowired
	private JwtAuthFilter JwtAuthFilter;
    
    @Autowired
    private UserDetailsService userDetailsService;
    
    @Bean 
     public AuthenticationProvider authenticationProvider() {
    	DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider(); // this bean will use the
    	// usernamepasswordauthtoken to do its authentication
    	authProvider.setPasswordEncoder(passwordEncoder());
    	authProvider.setUserDetailsService(userDetailsService);
    	return authProvider;
    }
    
    @Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
    
    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
    	return config.getAuthenticationManager();
    }
    
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http ) throws Exception {
		http.authorizeHttpRequests(auth -> auth.
				requestMatchers("/h2-console/**", "/api/v1/auth/register", "/api/v1/auth/authenticate").permitAll()		
				.anyRequest().authenticated());
		http.httpBasic(Customizer.withDefaults());
		http.csrf(csrf -> csrf.disable());
		http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
		http.headers(headers -> headers.frameOptions(frameOptions -> frameOptions.disable())); // disabling frame options
		http.authenticationProvider(authenticationProvider()).addFilterBefore(JwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
		return http.build();
	} 
	
	
	
}
