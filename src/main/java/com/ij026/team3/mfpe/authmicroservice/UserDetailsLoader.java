package com.ij026.team3.mfpe.authmicroservice;

import java.util.concurrent.ConcurrentHashMap;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import lombok.extern.log4j.Log4j2;

/**
 * @author Subham Santra
 *
 */
@Component
@Log4j2
public class UserDetailsLoader implements ApplicationRunner {

	private ConcurrentHashMap<String, String> userDetailsDB;
	
	/**
	 *  Initialize userDetailsDB
	 */
	public UserDetailsLoader() {
		this.userDetailsDB = new ConcurrentHashMap<>();
	}

	/**
	 * pre-populates the database
	 */
	@Override
	public void run(final ApplicationArguments args) throws Exception {
		final String defaultPassword = "abcd1234";
		userDetailsDB.put("guru", defaultPassword);
		userDetailsDB.put("rish", defaultPassword);
		userDetailsDB.put("subsa", defaultPassword);
		userDetailsDB.put("nikky", defaultPassword);
		userDetailsDB.put("ujjw", defaultPassword);
		log.debug("User details prepopulated!!");
	}

	/**
	 * @param empId
	 * @return password, if empId is valid, null otherwise
	 */
	public String getPassword(final String empId) {
		return userDetailsDB.getOrDefault(empId, null);
	}
}
