package telran.java2022.forum.post.dto;

import java.time.LocalDateTime;
import java.util.Set;

import lombok.Getter;
import lombok.Setter;
import telran.java2022.forum.post.model.Post.Comment;

@Getter
@Setter
public class PostDto {
	String id;
	String title;
	String content;
	String author;
	LocalDateTime dateCreated;
	Set<String> tags;
	Integer likes;
	Comment[] comments;
}
