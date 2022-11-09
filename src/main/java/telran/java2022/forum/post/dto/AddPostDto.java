package telran.java2022.forum.post.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AddPostDto {
	String title;
	String content;
	String[] tags;
}
