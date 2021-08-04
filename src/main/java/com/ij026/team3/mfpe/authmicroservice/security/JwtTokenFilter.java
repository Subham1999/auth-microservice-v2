package com.ij026.team3.mfpe.authmicroservice.security;

import java.io.IOException;
import java.util.Objects;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import lombok.NoArgsConstructor;

/**
 * @author <b>Subham Santra</b>
 *
 */
@Component
@NoArgsConstructor
public class JwtTokenFilter extends OncePerRequestFilter {

	@Autowired
	private JwtTokenUtil jwtTokenUtil;

	@Autowired
	private MyUserDetailsService userDetailsService;

	@Override
	protected void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response,
			final FilterChain filterChain) throws ServletException, IOException {

		final String authHeader = request.getHeader("Authorization");
		String userName = null;
		String jwtToken = null;

		if (Objects.nonNull(authHeader) && authHeader.startsWith("Bearer ")) {
			jwtToken = authHeader.substring(7);
			userName = jwtTokenUtil.extractUserName(jwtToken);
		}

		if (Objects.nonNull(userName) && Objects.nonNull(SecurityContextHolder.getContext().getAuthentication())) {
			final UserDetails loadUserByUsername = userDetailsService.loadUserByUsername(userName);

			if (jwtTokenUtil.validateToken(jwtToken, loadUserByUsername)) {
				final UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
						jwtToken, null, loadUserByUsername.getAuthorities());

				usernamePasswordAuthenticationToken
						.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

				SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
			}
		}

		filterChain.doFilter(request, response);
	}

}
