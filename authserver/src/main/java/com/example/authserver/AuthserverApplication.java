package com.example.authserver;

import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;

import javax.sql.DataSource;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@SpringBootApplication
public class AuthserverApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthserverApplication.class, args);
    }


}

@Configuration
class UsersConfiguration {

    @Bean
    JdbcUserDetailsManager jdbcUserDetailsManager(DataSource dataSource) {
        return new JdbcUserDetailsManager(dataSource);
    }

    @Bean
    ApplicationRunner usersRunner(UserDetailsManager userDetailsManager) {
        return args -> {
            var builder = User.builder().roles("USER");
            // pw for both is 'pw' (no quotes)
            var users = Map.of(
                    "jlong", "{bcrypt}$2a$10$w0eQPAJdEFW/ZmlwXyMZ2uyGq0B0FfzKy07TQCwO7G8pKHzlx4vIi",
                    "rwinch", "{bcrypt}$2a$10$U8VbtLIiUdM9ET4Ls8L.DeHifcAfU8yav1xnoJ7KT07yspcE7lpM6");
            users.forEach((username, password) -> {
                if (!userDetailsManager.userExists(username)) {
                    var user = builder
                            .username(username)
                            .password(password)
                            .build();
                    userDetailsManager.createUser(user);
                }
            });
        };
    }

}




@Configuration
class ClientsConfiguration {

    @Bean
    RegisteredClientRepository registeredClientRepository(JdbcTemplate template) {
        return new JdbcRegisteredClientRepository(template);
    }

    @Bean
    ApplicationRunner clientsRunner(RegisteredClientRepository repository) {
        return args -> {
            var clientId = "client";
            if (repository.findByClientId(clientId) == null) {
                repository.save(
                    RegisteredClient
                            .withId(UUID.randomUUID().toString())
                            .clientId(clientId)
                            .clientSecret("{bcrypt}$2a$10$g1/NkhNjXVBte07Kr85vB.ViP5FzvShGsKe.JNHvFrqQHg6g3HP2.")
                            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                            .authorizationGrantTypes(grantTypes -> grantTypes.addAll(Set.of(
                                    AuthorizationGrantType.CLIENT_CREDENTIALS,
                                    AuthorizationGrantType.AUTHORIZATION_CODE,
                                    AuthorizationGrantType.REFRESH_TOKEN)))
                            .redirectUri("http://127.0.0.1:8082/login/oauth2/code/spring")
                            .scopes(scopes -> scopes.addAll(
                                    Set.of("user.read", "user.write", OidcScopes.OPENID)))
                            .build()
                );
            }
        };
    }
}



@Configuration
class AuthorizationConfiguration {

    @Bean
    JdbcOAuth2AuthorizationConsentService jdbcOAuth2AuthorizationConsentService(
            JdbcOperations jdbcOperations, RegisteredClientRepository repository) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcOperations, repository);
    }

    @Bean
    JdbcOAuth2AuthorizationService jdbcOAuth2AuthorizationService(
            JdbcOperations jdbcOperations, RegisteredClientRepository rcr) {
        return new JdbcOAuth2AuthorizationService(jdbcOperations, rcr);
    }
}











