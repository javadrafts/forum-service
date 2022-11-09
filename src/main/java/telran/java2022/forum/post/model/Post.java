package telran.java2022.forum.post.model;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.springframework.data.mongodb.core.mapping.Document;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@EqualsAndHashCode(of = { "id" })
@Document(collection = "posts")
public class Post {
	String id;
	String title;
	String content;
	String author;
	LocalDateTime dateCreated = LocalDateTime.now();
	Set<String> tags = new HashSet<String>();
	Integer likes = 0;
	List<Comment> comments = new ArrayList<Comment>();

	public void addLike() {
		likes++;
	}

	public void addTags(Set<String> tags) {
		this.tags.addAll(tags);
	}

	@Getter
	@Setter
	public static class Comment {
		String user;
		String message;
		LocalDateTime dateCreated = LocalDateTime.now();
		Integer likes = 0;
	}
}
