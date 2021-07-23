package com.ij026.team3.mfpe.authmicroservice.security;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Service
public class JwtTokenUtil {
	// secret key
	private String SECRET_KEY = "SSBoYXRlIFBha2lzdGFuIGJ1dCBJIGxvdmUgSW5kaWE=";

	// one day
	private long LIFE_TIME = 24 * 60 * 60 * 1000l;

	public String extractUserName(String jwtToken) {
		return extractClaim(jwtToken, Claims::getSubject);
	}

	public Date extractExpiration(String jwtToken) {
		return extractClaim(jwtToken, Claims::getExpiration);
	}

	public <T> T extractClaim(String jwtToken, Function<Claims, T> claimsResolver) {
		final Claims claims = extractAllClaims(jwtToken);
		return claimsResolver.apply(claims);
	}

	public String generateToken(UserDetails userDetails) {
		Map<String, Object> claims = new HashMap<String, Object>();
		claims.put("ROLE", userDetails.getAuthorities());
		return createToken(claims, userDetails);
	}

	private String createToken(Map<String, Object> claims, UserDetails userDetails) {
		final Date issueDate = new Date();
		final Date expirationDate = new Date(issueDate.getTime() + LIFE_TIME);
		System.err.println("signing with key : " + SECRET_KEY);
		return Jwts.builder()
				.setClaims(claims)
				.setSubject(userDetails.getUsername())
				.setIssuedAt(issueDate)
				.setExpiration(expirationDate)
				.signWith(SignatureAlgorithm.HS256, SECRET_KEY).compact();
	}

	public Boolean validateToken(String jwtToken, UserDetails userDetails) {
		String userName = extractUserName(jwtToken);
		return (userName.equals(userDetails.getUsername()) && !isTokenExpired(jwtToken));
	}

	private boolean isTokenExpired(String jwtToken) {
		Date expirationDateAndTime = extractExpiration(jwtToken);
		Date currentDateAndTime = new Date();
		// return TRUE if expiration < currentDate
		return expirationDateAndTime.before(currentDateAndTime);
	}

	private Claims extractAllClaims(String jwtToken) {
		return Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(jwtToken).getBody();
	}

	public Boolean isValid(String jwtToken) {
		return !(isTokenExpired(jwtToken));
	}

	public String role(String jwtToken) {
		return "USER";
	}
}
