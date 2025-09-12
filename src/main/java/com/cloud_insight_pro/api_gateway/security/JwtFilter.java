package com.cloud_insight_pro.api_gateway.security;

import java.security.Key;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Slf4j
@Component
public class JwtFilter implements GlobalFilter, Ordered {
  @Value("${JWT_SECRET}")
  private String jwtSecret;

  public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

    HttpCookie tokenCookie = exchange.getRequest().getCookies().getFirst("token");

    log.info("JWT token found in cookie: {}", exchange.getRequest().getCookies());
    log.info("JWT token found in cookie: {}", jwt);

    if (tokenCookie != null) {
      String jwt = tokenCookie.getValue();
      log.info("JWT token found in cookie: {}", jwt);

      try {
        Claims claims = Jwts.parser()
            .verifyWith((SecretKey) key())
            .build()
            .parseSignedClaims(jwt)
            .getPayload();

        String userId = claims.getSubject();
        String role = claims.get("role", String.class);
        String fullName = claims.get("fullName", String.class);
        String email = claims.get("email", String.class);

        log.info("JWT validated. UserId: {}, Role: {}, Email: {}, FullName: {}", userId, role, email, fullName);

        ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
            .header("X-User-Id", String.valueOf(userId))
            .header("X-User-Role", role)
            .header("X-User-Email", email)
            .header("X-User-FullName", fullName)
            .build();

        return chain.filter(exchange.mutate().request(mutatedRequest).build());

      } catch (JwtException ex) {
        log.warn("Invalid JWT token: {}", ex.getMessage());
        return chain.filter(exchange);
      }
    } else {
      log.debug("No JWT token found in cookies.");
    }
    return chain.filter(exchange);
  }

  // Key encription
  private Key key() {
    log.debug("Decoding JWT secret for key generation.");
    return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
  }

  @Override
  public int getOrder() {
    return -1; // High precedence
  }
}
