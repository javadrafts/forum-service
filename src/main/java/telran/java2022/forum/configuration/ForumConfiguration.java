package telran.java2022.forum.configuration;

import org.modelmapper.ModelMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import telran.java2022.forum.post.dto.UpdatePostDto;
import telran.java2022.forum.post.model.Post;

@Configuration
public class ForumConfiguration {
	@Bean
	public ModelMapper getModelMapper() {
		ModelMapper modelMapper = new ModelMapper();

		modelMapper.getConfiguration()
			.setSkipNullEnabled(true);

		modelMapper.createTypeMap(UpdatePostDto.class, Post.class).addMappings(m -> {
			m.skip(Post::setTags);
			m.map(UpdatePostDto::getTags, Post::addTags);
		});

		return modelMapper;
	}
}
