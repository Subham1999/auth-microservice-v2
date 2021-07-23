package com.ij026.team3.mfpe.authmicroservice.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;

@EnableWebSecurity
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Autowired
	private MyUserDetailsService myUserDetailsService;

	@Autowired
	private JwtTokenFilter jwtTokenFilter;

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(myUserDetailsService);
	}

	@Override
	protected void configure(HttpSecurity httpSecurity) throws Exception {
//		http.authorizeRequests()
//		.antMatchers("/public/test", "/authenticate", "/authorize-token", "/health").permitAll()
//				.and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
//				.addFilterBefore(jwtTokenFilter, UsernamePasswordAuthenticationFilter.class);//.exceptionHandling();
		
		httpSecurity.csrf().disable()
		.authorizeRequests().antMatchers("/authenticate", "/public/**").permitAll()
		.anyRequest()
		.authenticated()
		.and()
		.exceptionHandling()
		.and().sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
		httpSecurity.addFilterBefore(jwtTokenFilter, UsernamePasswordAuthenticationFilter.class);

	}

	@Bean
	public PasswordEncoder passwordEncoder() {
//	return new BCryptPasswordEncoder();
		return NoOpPasswordEncoder.getInstance();
	}

	@Override
	@Bean
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

}
