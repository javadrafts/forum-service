package telran.java2022.forum.user.dto.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class PasswordIncorrectException extends RuntimeException {
	private static final long serialVersionUID = -147098629396473061L;

	public PasswordIncorrectException() {
		super("Password is incorrect.");
	}
}
