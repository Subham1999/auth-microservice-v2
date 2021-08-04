package com.ij026.team3.mfpe.authmicroservice.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.test.web.servlet.MockMvc;

import com.ij026.team3.mfpe.authmicroservice.UserDetailsLoader;
import com.ij026.team3.mfpe.authmicroservice.security.JwtTokenUtil;
import com.ij026.team3.mfpe.authmicroservice.security.MyUserDetailsService;

//@SpringBootTest(webEnvironment = WebEnvironment.MOCK)
@WebMvcTest
class AuthControllerTest {

	@MockBean
	private AuthenticationManager authenticationManager;

	@MockBean
	private JwtTokenUtil jwtTokenUtil;

	@MockBean
	private MyUserDetailsService userDetailsService;

	@MockBean
	private UserDetailsLoader loader;

	@Autowired
	@InjectMocks
	private AuthController authController;

	private String validJwtToken;
	private String inValidJwtToken;

	private String validEmpId;
	private String inValidEmpId;

	@Autowired
	private MockMvc mockMvc;

	@BeforeAll
	static void setUpBeforeClass() throws Exception {
	}

	@AfterAll
	static void tearDownAfterClass() throws Exception {
	}

	@BeforeEach
	void setUp() throws Exception {
		validJwtToken = "subsa";
		inValidJwtToken = "inValid";
		validEmpId = "valid_";
		inValidEmpId = "inValid_";
	}

	@AfterEach
	void tearDown() throws Exception {
		validJwtToken = inValidJwtToken = validEmpId = inValidEmpId = null;
	}

	@Test
	void testPubTest() {
		assertEquals("Test", this.authController.pubTest());
	}

	@Test
	void testCreateAuthenticationToken_allValid() throws Exception {
		String json = "{\"userName\" : \"subsa\", \"password\" : \"abcd1234\"}";
		mockMvc.perform(post("/authenticate").contentType(MediaType.APPLICATION_JSON).content(json))
				.andExpect(status().isOk());
	}

	@Test
	void testAuthorizeToken() throws Exception {
		when(this.jwtTokenUtil.isTokenNotExpired(validJwtToken)).thenReturn(true);
		when(this.jwtTokenUtil.extractUserName(validJwtToken)).thenReturn(validEmpId);
		when(this.loader.getPassword(validEmpId)).thenReturn("abcd1234");

		mockMvc.perform(post("/authorize-token").header("Authorization", "Bearer " + this.validJwtToken))
				.andExpect(status().isOk());
	}

	@Test
	void testAuthorizeToken_invalidToken() throws Exception {
		when(this.jwtTokenUtil.isTokenNotExpired(validJwtToken)).thenReturn(false);
		mockMvc.perform(post("/authorize-token").header("Authorization", "Bearer " + this.validJwtToken))
				.andExpect(status().isBadRequest());
	}

	@Test
	void testHandleBadCredentialsException() {

		ResponseEntity<String> actual = this.authController
				.handleBadCredentialsException(new BadCredentialsException("test"));

		ResponseEntity<String> expected = ResponseEntity.status(HttpStatus.BAD_REQUEST).body("test");

		assertEquals(expected, actual);
	}

//	@Test
//	void testHandleMissingRequestHeaderException() {
//		fail("Not yet implemented");
//	}
//
//	@Test
//	void testHandleExpiredJwtException() {
//		fail("Not yet implemented");
//	}

}
