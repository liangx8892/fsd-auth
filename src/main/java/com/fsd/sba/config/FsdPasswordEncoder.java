package com.fsd.sba.config;

import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class FsdPasswordEncoder extends BCryptPasswordEncoder{
	
	private static final Logger logger = LoggerFactory.getLogger(FsdPasswordEncoder.class);
	private Pattern BCRYPT_PATTERN = Pattern
			.compile("\\A\\$2a?\\$\\d\\d\\$[./0-9A-Za-z]{53}");
	
	@Override
	public boolean matches(CharSequence rawPassword, String encodedPassword) {
		if (encodedPassword == null || encodedPassword.length() == 0) {
			logger.warn("Empty encoded password");
			return false;
		}

		if (!BCRYPT_PATTERN.matcher(encodedPassword).matches()) {
			logger.warn("Encoded password does not look like BCrypt");
			return false;
		}

		boolean result = BCrypt.checkpw(rawPassword.toString(), encodedPassword);
		logger.error("rawPassword {} , encodedPassword {}, is matched : {}", rawPassword, encodedPassword, result);
		return result;
	}
}
