package com.example.processor;


import org.springframework.amqp.core.*;
import org.springframework.amqp.rabbit.connection.ConnectionFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.integration.amqp.dsl.Amqp;
import org.springframework.integration.dsl.DirectChannelSpec;
import org.springframework.integration.dsl.IntegrationFlow;
import org.springframework.integration.dsl.MessageChannels;
import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.support.ChannelInterceptor;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.messaging.access.intercept.AuthorizationChannelInterceptor;
import org.springframework.security.messaging.context.SecurityContextChannelInterceptor;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.util.Assert;

@SpringBootApplication
public class ProcessorApplication {

	public static void main(String[] args) {
		SpringApplication.run(ProcessorApplication.class, args);
	}

}


class Names {

    public static final String RABBITMQ_DESTINATION_NAME = "emails";

    public static final String AUTHORIZATION_HEADER_NAME = "jwt";
}


@Configuration
class IntegrationConfiguration {

    @Bean
	IntegrationFlow inboundRequestsIntegrationFlowPreAuthorization(
			MessageChannel requests, ConnectionFactory connectionFactory) {
        var inboundAmqpAdapter = Amqp
                .inboundAdapter(connectionFactory, Names.RABBITMQ_DESTINATION_NAME);
        return IntegrationFlow
                .from(inboundAmqpAdapter)
                .channel(requests)
                .get();
    }

    @Bean
    IntegrationFlow inboundRequestsIntegrationFlowPostAuthorization(MessageChannel requests) {
        return IntegrationFlow
                .from(requests)//
                .handle((payload, headers) -> {
                    System.out.println("------------------------------------------------------------------------------");
                    System.out.println(payload.toString());
                    headers.forEach((key, value) -> System.out.println(key + '=' + value));
                    return null;
                })//
                .get();
    }

    @Bean
	DirectChannelSpec requests(JwtAuthenticationProvider jwtAuthenticationProvider) {
        return MessageChannels
                .direct()
                .interceptor(
                        new JwtAuthenticationInterceptor(Names.AUTHORIZATION_HEADER_NAME, jwtAuthenticationProvider),
                        new SecurityContextChannelInterceptor(Names.AUTHORIZATION_HEADER_NAME),
                        new AuthorizationChannelInterceptor(AuthenticatedAuthorizationManager.authenticated()));
    }

    @Bean
	Queue queue() {
        return QueueBuilder.durable(Names.RABBITMQ_DESTINATION_NAME).build();
    }

    @Bean
	Exchange exchange() {
        return ExchangeBuilder.directExchange(Names.RABBITMQ_DESTINATION_NAME).build();
    }

    @Bean
	Binding binding() {
        return BindingBuilder.bind(queue()).to(exchange()).with(Names.RABBITMQ_DESTINATION_NAME).noargs();
    }

}

@Configuration
class SecurityConfiguration {

    @Bean
    JwtAuthenticationProvider jwtAuthenticationProvider(JwtDecoder decoder) {
        return new JwtAuthenticationProvider(decoder);
    }

    @Bean
	JwtDecoder jwtDecoder(@Value("${spring.security.oauth2.authorizationserver.issuer}") String issuerUri) {
        return NimbusJwtDecoder.withIssuerLocation(issuerUri).build();
    }

    @Bean
	JwtAuthenticationConverter jwtAuthenticationConverter() {
        return new JwtAuthenticationConverter();
    }
}

class JwtAuthenticationInterceptor implements ChannelInterceptor {

    private final JwtAuthenticationProvider authenticationProvider;

    private final String headerName;

    JwtAuthenticationInterceptor(String headerName, JwtAuthenticationProvider ap) {
        this.headerName = headerName;
        this.authenticationProvider = ap;
    }


	@Override
    public org.springframework.messaging.Message<?> preSend(Message<?> message, MessageChannel channel) {
        var token = (String) message.getHeaders().get(headerName);
        Assert.hasText(token, "the token must be non-empty!");
        var authentication = this.authenticationProvider.authenticate(new BearerTokenAuthenticationToken(token));
        if (authentication != null && authentication.isAuthenticated()) {
            var upt = UsernamePasswordAuthenticationToken.authenticated(authentication.getName(),
                    null, AuthorityUtils.NO_AUTHORITIES);
            return org.springframework.messaging.support.MessageBuilder
                    .fromMessage(message)
                    .setHeader(headerName, upt)
                    .build();
        }
        return MessageBuilder
                .fromMessage(message)
                .setHeader(headerName, null)
                .build();
    }
}