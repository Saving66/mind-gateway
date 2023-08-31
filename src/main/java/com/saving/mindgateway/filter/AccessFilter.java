package com.saving.mindgateway.filter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.saving.mind.common.constant.RedisConstant;
import com.saving.mind.common.constant.UserInfoConstant;
import com.saving.mind.common.excpetion.BusinessException;
import com.saving.mind.common.utils.JwtUtil;
import com.saving.mind.common.model.TokenInfo;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwt;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.annotation.Resource;
import java.nio.charset.StandardCharsets;

/**
 * @author saving
 */

@Component
public class AccessFilter implements GlobalFilter, Ordered {

    @Resource
    private RedisTemplate redisTemplate;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        ServerHttpResponse response = exchange.getResponse();
        try {
            // 获取请求对象
            ServerHttpRequest request = exchange.getRequest();

            // 从请求头获取Token类型
            String tokenType = request.getHeaders().getFirst("Token-Type");

            // 从请求头中获取Token
            String token = request.getHeaders().getFirst("Authorization");

            if ("Access".equals(tokenType)) {
                // 对AccessToken进行验证
                TokenInfo tokenInfo = JwtUtil.extractObject(token, UserInfoConstant.JWT_KEY, TokenInfo.class, UserInfoConstant.USER_ACCESS_TOKEN);
                Object o = redisTemplate.opsForValue().get(RedisConstant.USER_ACCESS_TOKEN_KEY + tokenInfo.getUserId());
                if (o == null) {
                    return onError(exchange, "Token Expired", HttpStatus.UNAUTHORIZED);
                }
                exchange.getRequest().mutate().header("X-Custom-User-Id", tokenInfo.getUserId().toString()).build();
            } else if ("Refresh".equals(tokenType)) {
                // 对RefreshToken进行验证
                TokenInfo tokenInfo = JwtUtil.extractObject(token, UserInfoConstant.JWT_KEY, TokenInfo.class, UserInfoConstant.USER_REFRESH_TOKEN);
                String accessToken = JwtUtil.generateToken(tokenInfo, UserInfoConstant.JWT_KEY, UserInfoConstant.USER_ACCESS_TOKEN_EXPIRED_TIME, UserInfoConstant.USER_ACCESS_TOKEN);
                DataBuffer buffer = response.bufferFactory().wrap(accessToken.getBytes(StandardCharsets.UTF_8));
                response.getHeaders().setContentType(MediaType.TEXT_PLAIN);
                return response.writeWith(Mono.just(buffer));
            } else {
                // 无效的Token类型
                return onError(exchange, "Invalid Token Type", HttpStatus.UNAUTHORIZED);
            }
        } catch (JsonProcessingException e) {
            // Token解析失败
            return onError(exchange, "Token Parse Error", HttpStatus.UNAUTHORIZED);
        } catch (ExpiredJwtException e) {
            // Token过期
            return onError(exchange, "Token Expired", HttpStatus.UNAUTHORIZED);
        } catch (BusinessException e) {
            // Token类型不匹配
            return onError(exchange, "Token Type Error", HttpStatus.UNAUTHORIZED);
        }

        return chain.filter(exchange);
    }

    @Override
    public int getOrder() {
        return -100;
    }


    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);

        // 设置响应头为application/json
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        // 创建一个DataBuffer，并写入错误信息
        DataBuffer buffer = response.bufferFactory().wrap(err.getBytes(StandardCharsets.UTF_8));

        // 写入响应体
        return response.writeWith(Mono.just(buffer));
    }
}
