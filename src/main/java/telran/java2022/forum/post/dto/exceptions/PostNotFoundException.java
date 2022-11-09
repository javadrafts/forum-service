package telran.java2022.forum.post.dto.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.NOT_FOUND)
public class PostNotFoundException extends RuntimeException {
	private static final long serialVersionUID = 9009695521234500389L;

	public PostNotFoundException(String id) {
		super("Post " + id + " not found.");
	}
}
