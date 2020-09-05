package telran.ashkelon2020.accounting.security.configuration;

import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

//@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityAuthorizationConfiguration extends WebSecurityConfigurerAdapter {
	
	@Override
	public void configure(WebSecurity web) {
		web.ignoring().antMatchers("/account/register");
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception{
		http.httpBasic();
		http.csrf().disable();
		http.authorizeRequests()
		.antMatchers(HttpMethod.GET).permitAll()
		.antMatchers(HttpMethod.POST, "/forum/posts/**").permitAll()
		//check expDate and has roles for login and addLike
		.antMatchers("/account/login**", "/forum/post/{id}/like**")
			.access("@customSecurity.checkExpDate(authentication.name) "
						+ "and hasAnyRole('ADMINISTRATOR', 'MODERATOR', 'USER')")
		//check expDate, has roles and validate for updateUser, addComment
		.antMatchers(HttpMethod.PUT, "/account/user/{login}**", "/forum/post/{id}/comment/{author}**")
			.access("@customSecurity.checkExpDate(authentication.name) "
						+ "and hasAnyRole('ADMINISTRATOR', 'MODERATOR', 'USER') "
						+ "and (#login==authentication.name or #author==authentication.name)")
		//check expDate, has roles and validate for addPost 
		.antMatchers(HttpMethod.POST, "/forum/post/{author}**")
			.access("@customSecurity.checkExpDate(authentication.name) "
						+ "and hasAnyRole('ADMINISTRATOR', 'MODERATOR', 'USER') "
						+ "and #author==authentication.name")
		//check ROLE_ADMIN for addRole/removeRole
		.antMatchers("/account/user/{login}/role/{role}**")
			.hasRole("ADMINISTRATOR") 
		// validate user for removeUser
		.antMatchers(HttpMethod.DELETE, "/account/user/{login}**")
			.access("#login==authentication.name") 
		//check expDate, has roles, validate user or moderator for updatePost
		.antMatchers(HttpMethod.PUT,"/forum/post/{id}**")
			.access("@customSecurity.checkExpDate(authentication.name) "
						+ "and hasAnyRole('ADMINISTRATOR', 'MODERATOR', 'USER') "
						+ "and (@customSecurity.checkPostAuthority(#id, authentication.name) or hasRole('MODERATOR'))") 
		//check expDate, has roles, validate user or moderator for removePost
		.antMatchers(HttpMethod.DELETE,"/forum/post/{id}**")
			.access("@customSecurity.checkExpDate(authentication.name) "
						+ "and hasAnyRole('ADMINISTRATOR', 'MODERATOR', 'USER') "
						+ "and (@customSecurity.checkPostAuthority(#id, authentication.name) or hasRole('MODERATOR'))")
		.antMatchers("/account/password**")
			.authenticated()
		.anyRequest()
			.authenticated();
		
		
	}
}
