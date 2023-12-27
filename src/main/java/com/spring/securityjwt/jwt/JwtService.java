package com.spring.securityjwt.jwt;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import javax.crypto.SecretKey;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {
	
    static final String ENCRYPTION_KEY  = "pBlil45u1nPAJgCwlhWuLezPpGN/c7Ss6pN61adIucxix3+0gDXf+tF0+czymCJSSKYugiVMHV5umxtCkKCGtKm4aUxspGPqCUegzqFlQsInMMXC1IWPmmabgA9Y8cL6kyyLz/XQo02PSBAmczJHWANWmDrKqUwO/eIb9U1GAdAaZQapXw56Yjnc1jNlKTcznFx9aGw4XbGh2/QVo5GqIrnGulmVExIpCqLIVydb6pq7VsmqtLrDL1nzARNRZfOoKXp74Ogt2t2GlIAl2oVm1x4nHfVxdXVGPJXX/rot0fEcFqsAf74sOInwMo0qTJ+byVdj7rrsr7fExJetrAUJIm8/U3AiU0pcAS5Tr0wJjXM=\r\n";
	public String extractUsername(String jwtToken) {
		return  extractClaim(jwtToken, Claims::getSubject);
	}
	
	// a generic method for extracting a claim from a valid jwt token
	public <T> T extractClaim(String token, Function<Claims, T> claimExtractor) {
	   Claims claims = extractAllClaims(token);
	   return claimExtractor.apply(claims);
	}
	
	
	public String generateJwtToken(Map<String, Object> extraClaims, UserDetails user) {
		
		return Jwts.builder().claims(extraClaims).
				subject(user.getUsername()).
				issuedAt(new Date(System.currentTimeMillis())).
				expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24 )). // expires in 24 hours
				signWith(getKey()).
				compact();
	}
	
	// overload function to generate a token without extra claims
	public String generateJwtToken(UserDetails user) {
		
		return Jwts.builder().claims(new HashMap<>()).
				subject(user.getUsername()).
				issuedAt(new Date(System.currentTimeMillis())).
				expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24 )). // expires in 24 hours
				signWith(getKey()).
				compact();
	}
		

	public Claims extractAllClaims(String jwtToken) {
		return Jwts.parser().
				verifyWith(getKey()).
				build().
				parseSignedClaims(jwtToken).
				getPayload();
	}

	
     private SecretKey getKey() {
		SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(ENCRYPTION_KEY));
		return key;
	}
     
     
     public boolean isTokenValid(String token, UserDetails user) {
    	 String username = user.getUsername();
    	 Date expirationDate = extractClaim(token, Claims::getExpiration);
    	 
    	 return expirationDate.before(new Date()) && username.equals(extractUsername(token)); // 
    	 // we are want to make sure that the token has not expired and that it belongs to the user who is trying 
    	 // to access our resources
     }
	

}



