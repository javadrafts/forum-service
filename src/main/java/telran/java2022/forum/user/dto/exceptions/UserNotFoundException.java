package telran.java2022.forum.user.dto.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.NOT_FOUND)
public class UserNotFoundException extends RuntimeException {
	private static final long serialVersionUID = 1798460795072025753L;

	public UserNotFoundException(String login) {
		super("User '" + login + "' not found.");
	}
}
