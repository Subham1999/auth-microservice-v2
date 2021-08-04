package com.ij026.team3.mfpe.authmicroservice.controller;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.MissingRequestHeaderException;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import com.ij026.team3.mfpe.authmicroservice.UserDetailsLoader;
import com.ij026.team3.mfpe.authmicroservice.security.JwtTokenUtil;
import com.ij026.team3.mfpe.authmicroservice.security.MyUserDetailsService;
import com.ij026.team3.mfpe.authmicroservice.security.model.AuthRequest;
import com.ij026.team3.mfpe.authmicroservice.security.model.AuthResponse;

import io.jsonwebtoken.ExpiredJwtException;

@RestController
public class AuthController {

	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private JwtTokenUtil jwtTokenUtil;

	@Autowired
	private MyUserDetailsService userDetailsService;

	@Autowired
	private UserDetailsLoader loader;

	@GetMapping("/public/test")
	public String pubTest() {
		return "Test";
	}

	@CrossOrigin
	@PostMapping(value = "/authenticate")
	public ResponseEntity<AuthResponse> createAuthenticationToken(HttpServletRequest httpServletRequest,
			@RequestBody AuthRequest authenticationRequest) {

		authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authenticationRequest.getUserName(),
				authenticationRequest.getPassword()));

		final UserDetails userDetails = userDetailsService.loadUserByUsername(authenticationRequest.getUserName());

		final String jwt = jwtTokenUtil.generateToken(userDetails);
		AuthResponse authResponse = new AuthResponse(jwt, httpServletRequest.getRequestURL().toString(),
				httpServletRequest.getRemoteAddr());
		return ResponseEntity.ok(authResponse);
	}

	@CrossOrigin
	@PostMapping(value = "/authorize-token")
	public ResponseEntity<String> authorizeToken(
			@RequestHeader(value = "Authorization", required = true) String authorizationHeaderVal) {
		String jwtToken = extractTokenFromHeader(authorizationHeaderVal);
		Boolean valid = jwtTokenUtil.isTokenNotExpired(jwtToken);
		if (valid) {
			String userName = jwtTokenUtil.extractUserName(jwtToken);
			String password = loader.getPassword(userName);
			if (password == null) {
				return ResponseEntity.badRequest().body("empId invalid");
			} else {
				return ResponseEntity.ok(userName);
			}
		}
		return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("jwt token expired");
	}

	private String extractTokenFromHeader(String authorizationHeaderVal) {
		// [Bearer ][***jwtToken***]
		return authorizationHeaderVal.substring(7);
	}

	@ExceptionHandler(BadCredentialsException.class)
	public ResponseEntity<String> handleBadCredentialsException(BadCredentialsException badCredentialsException) {
		return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(badCredentialsException.getMessage());
	}

	@ExceptionHandler(MissingRequestHeaderException.class)
	public ResponseEntity<String> handleMissingRequestHeaderException(
			MissingRequestHeaderException missingRequestHeaderException) {
		return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(missingRequestHeaderException.getMessage());
	}

	@ExceptionHandler(ExpiredJwtException.class)
	public ResponseEntity<String> handleExpiredJwtException(ExpiredJwtException expiredJwtException) {
		return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(expiredJwtException.getMessage());
	}
}
