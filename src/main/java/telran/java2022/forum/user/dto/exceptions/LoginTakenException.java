package telran.java2022.forum.user.dto.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.CONFLICT)
public class LoginTakenException extends RuntimeException {
	private static final long serialVersionUID = 2589178213327828884L;

	public LoginTakenException(String login) {
		super("Login '" + login + "' already taken.");
	}
}
