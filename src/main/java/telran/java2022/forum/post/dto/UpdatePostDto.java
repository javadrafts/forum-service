package telran.java2022.forum.post.dto;

import java.util.Set;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UpdatePostDto {
	String title;
	Set<String> tags;
}
