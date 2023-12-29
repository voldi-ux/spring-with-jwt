package com.spring.securityjwt.filters;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.spring.securityjwt.jwt.JwtService;
import com.spring.securityjwt.users.User;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;


// oncePerRequestFilter fires once for every request to our application
@Component // making this filter a managed bean
public class JwtAuthFilter  extends OncePerRequestFilter{
	 @Autowired
     private  JwtService jwtService;
	 @Autowired
	private  UserDetailsService userDetailsSerice;
	 
	@Override
	protected void doFilterInternal(HttpServletRequest request,
			HttpServletResponse response,
			FilterChain filterChain)
			throws ServletException, IOException {
          	final String authorizationHeader = request.getHeader("Authorization");
          	final String jwtToken;
          	final String username;
          
          	
          	// if the authorization header is missing or is invalid then we ignore the request
          	if((authorizationHeader == null || !authorizationHeader.startsWith("Bearer "))) {
          		filterChain.doFilter(request, response);
          		return;
          	}
          	
          	jwtToken = authorizationHeader.substring(7);
          	
          	// we need to get the username from the jwt token
          	username = jwtService.extractUsername(jwtToken);
          	SecurityContext context = SecurityContextHolder.getContext();
          	
			if (username != null && context.getAuthentication() == null) {
          		User user = (User) userDetailsSerice.loadUserByUsername(username);
          		if(jwtService.isTokenValid(jwtToken, user)) {
          			UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, null, user.getAuthorities() );
          			authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request)); // we are setting extra details 
          			// which we may want to use later. We can specify any object we want in the setDetails method call
                      
          			context.setAuthentication(authToken); // we are now setting the user in the security context
          			
          		}          		
          		
          	}
          	
		
			filterChain.doFilter(request, response);
          	
	}

}










