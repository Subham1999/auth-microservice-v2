package com.ij026.team3.mfpe.authmicroservice;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import com.ij026.team3.mfpe.authmicroservice.controller.AuthController;
import com.ij026.team3.mfpe.authmicroservice.security.JwtTokenFilter;
import com.ij026.team3.mfpe.authmicroservice.security.JwtTokenUtil;
import com.ij026.team3.mfpe.authmicroservice.security.MyUserDetailsService;
import com.ij026.team3.mfpe.authmicroservice.security.WebSecurityConfiguration;

@SpringBootTest
class AuthMicroserviceApplicationTests {

	@Autowired
	private UserDetailsLoader userDetailsLoader;
	@Autowired
	private MyUserDetailsService myUserDetailsService;
	@Autowired
	private JwtTokenFilter jwtTokenFilter;
	@Autowired
	private JwtTokenUtil jwtTokenUtil;
	@Autowired
	private WebSecurityConfiguration webSecurityConfiguration;
	@Autowired
	private AuthController authController;

	@Test
	void contextLoads() {
		assertThat(this.authController).isNotNull();
		assertThat(this.jwtTokenFilter).isNotNull();
		assertThat(this.jwtTokenUtil).isNotNull();
		assertThat(this.myUserDetailsService).isNotNull();
		assertThat(this.userDetailsLoader).isNotNull();
		assertThat(this.webSecurityConfiguration).isNotNull();
	}

}
