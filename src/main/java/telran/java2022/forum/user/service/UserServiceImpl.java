package telran.java2022.forum.user.service;

import org.mindrot.jbcrypt.BCrypt;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import telran.java2022.forum.user.dao.UserRepository;
import telran.java2022.forum.user.dto.RegisterDto;
import telran.java2022.forum.user.dto.UpdateUserDto;
import telran.java2022.forum.user.dto.UserDto;
import telran.java2022.forum.user.dto.exceptions.LoginTakenException;
import telran.java2022.forum.user.dto.exceptions.UserNotFoundException;
import telran.java2022.forum.user.model.User;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
	final UserRepository userRepository;
	final ModelMapper modelMapper;

	@Override
	public UserDto register(RegisterDto registerDto) {
		userRepository.findById(registerDto.getLogin())
			.ifPresent(u -> {
				throw new LoginTakenException(registerDto.getLogin());
			});

		User user = modelMapper.map(registerDto, User.class);

		user.setPassword(BCrypt.hashpw(registerDto.getPassword(), BCrypt.gensalt()));

		user = userRepository.save(user);

		return modelMapper.map(user, UserDto.class);
	}

	@Override
	public UserDto login(String login) {
		User user = userRepository.findById(login)
				.orElseThrow(() -> new UserNotFoundException(login));

		return modelMapper.map(user, UserDto.class);
	}

	@Override
	public UserDto deleteUser(String login) {
		User user = userRepository.findById(login)
				.orElseThrow(() -> new UserNotFoundException(login));

		userRepository.delete(user);

		return modelMapper.map(user, UserDto.class);
	}

	@Override
	public UserDto updateUser(String login, UpdateUserDto updateUserDto) {
		User user = userRepository.findById(login)
				.orElseThrow(() -> new UserNotFoundException(login));

		modelMapper.map(updateUserDto, user);

		user = userRepository.save(user);

		return modelMapper.map(user, UserDto.class);
	}

	@Override
	public UserDto addRole(String login, String role) {
		User user = userRepository.findById(login)
				.orElseThrow(() -> new UserNotFoundException(login));

		user.getRoles().add(role);

		user = userRepository.save(user);

		return modelMapper.map(user, UserDto.class);
	}

	@Override
	public UserDto deleteRole(String login, String role) {
		User user = userRepository.findById(login)
				.orElseThrow(() -> new UserNotFoundException(login));

		user.getRoles().remove(role);

		user = userRepository.save(user);

		return modelMapper.map(user, UserDto.class);
	}

	@Override
	public void changePassword(String login, String newPassword) {
		User user = userRepository.findById(login)
				.orElseThrow(() -> new UserNotFoundException(login));

		user.setPassword(BCrypt.hashpw(newPassword, BCrypt.gensalt()));

		user = userRepository.save(user);
	}
}
