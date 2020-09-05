package telran.ashkelon2020.accounting.security.service;

import java.time.LocalDateTime;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import telran.ashkelon2020.accounting.dao.UserAccountRepository;
import telran.ashkelon2020.accounting.dto.exceptions.UserNotFoundException;
import telran.ashkelon2020.accounting.model.UserAccount;
import telran.ashkelon2020.forum.dao.PostRepository;
import telran.ashkelon2020.forum.model.Post;

@Service("customSecurity")
public class CustomWebSecurityService {

	@Autowired
	PostRepository postRepository;
	
	@Autowired
	UserAccountRepository userRepository;
	
	public boolean checkPostAuthority(String id, String user) {
		Post post = postRepository.findById(id).orElse(null);
		return post == null ? true : post.getAuthor().equals(user);		
	}
	
	public boolean checkExpDate(String login) {
		UserAccount user = userRepository.findById(login).orElseThrow(() -> new UserNotFoundException(login));
		return user.getExpDate().isAfter(LocalDateTime.now()); 
	}
}
