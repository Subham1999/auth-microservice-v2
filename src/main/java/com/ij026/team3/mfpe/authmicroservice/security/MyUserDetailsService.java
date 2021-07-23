package com.ij026.team3.mfpe.authmicroservice.security;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.ij026.team3.mfpe.authmicroservice.UserDetailsLoader;

@Service
public class MyUserDetailsService implements UserDetailsService {

	@Autowired
	private UserDetailsLoader loader;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

		String password = loader.getPassword(username);
		if (password == null) {
			throw new UsernameNotFoundException("username : " + username + " not found!");
		} else {
			return new User(username, password, true, true, true, true,
					List.of(new SimpleGrantedAuthority("ROLE_USER")));
		}
	}

}
